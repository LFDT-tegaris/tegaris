import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { startPgCommitFault } from './withdrawal-commit-fault.mjs';

export const sourceImportQuery = `insert into control.runtime_configuration_input
            (participant_id,privacy_domain_id,module_installation_id,module_configuration_generation_id,
             configuration_cbor,configuration_digest,resource_bindings,selected,runtime_configuration_input_id)
            values ($1::text::uuid,$2::text::uuid,$3::text::uuid,$4::text::uuid,$5,sha256($5),$6,true,$7::text::uuid)
            on conflict (participant_id,privacy_domain_id,module_configuration_generation_id,configuration_digest)
            do update set selected=true`;
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
function cstring(bytes, offset = 0) {
  const end = bytes.indexOf(0, offset);
  assert.ok(end >= offset);
  return [bytes.toString('utf8', offset, end), end + 1];
}

// Correlate only the real source INSERT, its seven actual bound values and its
// successful containing COMMIT. Startup, unrelated transactions and rollbacks
// cannot consume this fault; no SQL or admission is manufactured by the proxy.
export class SourceImportCommitCorrelation {
  constructor({ participant, privacy, configurationDigest }) {
    assert.match(participant, uuid);
    assert.match(privacy, uuid);
    assert.match(configurationDigest, /^[0-9a-f]{64}$/u);
    Object.assign(this, { participant, privacy, configurationDigest });
    this.statements = new Map();
    this.portals = new Map();
    this.pending = [];
    this.imported = null;
  }
  frontend(tag, body) {
    if (tag === 'P') {
      const [name, offset] = cstring(body);
      this.statements.set(name, cstring(body, offset)[0] === sourceImportQuery);
    } else if (tag === 'B') {
      const [portal, offset] = cstring(body);
      const [statement, start] = cstring(body, offset);
      let identity = null;
      if (this.statements.get(statement)) {
        let cursor = start;
        const formats = body.readUInt16BE(cursor);
        assert.ok(formats === 0 || formats === 1 || formats === 7);
        cursor += 2 + 2 * formats;
        assert.equal(body.readUInt16BE(cursor), 7);
        cursor += 2;
        const values = [];
        for (let i = 0; i < 7; i++) {
          const length = body.readInt32BE(cursor);
          cursor += 4;
          assert.ok(length >= 0 && length <= 16 * 1024 * 1024 && cursor + length <= body.length);
          values.push(body.subarray(cursor, cursor + length));
          cursor += length;
        }
        if (
          values[0].toString() === this.participant &&
          values[1].toString() === this.privacy &&
          hash(values[4]) === this.configurationDigest
        ) {
          for (const index of [2, 3, 6]) assert.match(values[index].toString(), uuid);
          identity = {
            input_id: values[6].toString(),
            module_installation_id: values[2].toString(),
            module_configuration_generation_id: values[3].toString(),
            configuration_digest: this.configurationDigest,
          };
        }
      }
      this.portals.set(portal, identity);
    } else if (tag === 'E') {
      const [portal, offset] = cstring(body);
      assert.equal(body.readUInt32BE(offset), 0);
      this.pending.push({ identity: this.portals.get(portal), command: null });
    } else if (tag === 'Q') {
      const [query, end] = cstring(body);
      assert.equal(end, body.length);
      this.pending.push({ identity: null, command: query.trim().toUpperCase() });
    } else if (tag === 'C') {
      const [name] = cstring(body, 1);
      if (body[0] === 83) this.statements.delete(name);
      else if (body[0] === 80) this.portals.delete(name);
    }
    assert.ok(this.statements.size <= 512 && this.portals.size <= 512 && this.pending.length <= 64);
  }
  backend(tag, body) {
    if (tag === 'E' || tag === 'Z') {
      this.pending = [];
      if (tag === 'E' || body[0] !== 84) this.imported = null;
    } else if (tag === 'C') {
      const command = cstring(body)[0],
        executed = this.pending.shift();
      if (command === 'COMMIT') {
        const identity = executed?.command === 'COMMIT' ? this.imported : null;
        this.imported = null;
        return identity;
      }
      if (command === 'ROLLBACK' || command === 'BEGIN') this.imported = null;
      if (command === 'INSERT 0 1' && executed?.identity) this.imported = executed.identity;
    } else if (tag === 'I') this.pending.shift();
    return null;
  }
}

export function startSourceImportCommitFault({
  participant,
  privacy,
  configurationDigest,
  ...options
}) {
  const scope = { participant, privacy, configurationDigest };
  return startPgCommitFault({
    ...options,
    correlationFactory: () => new SourceImportCommitCorrelation(scope),
    describeCommit: (identity) => ({ ...identity, count: 1 }),
  });
}
