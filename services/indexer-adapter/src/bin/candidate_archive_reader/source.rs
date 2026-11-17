use pc_provider_api::{decode_client_indexer_profile_pc_cbor, validate_canonical_pc_cbor_bytes};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use uuid::Uuid;

type Result<T> = std::result::Result<T, &'static str>;
const MAX_PAYLOAD: usize = 1_048_576;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Request {
    pub participant_id: Uuid,
    pub privacy_domain_id: Uuid,
    pub source_profile_id: Uuid,
    pub generation_id: Uuid,
    pub partition_id: Uuid,
    pub candidate_id: Uuid,
}
impl Request {
    pub fn validate(&self) -> Result<()> {
        if [
            self.participant_id,
            self.privacy_domain_id,
            self.source_profile_id,
            self.generation_id,
            self.partition_id,
            self.candidate_id,
        ]
        .iter()
        .any(|id| id.get_version_num() != 7)
        {
            return Err("candidate identity rejected");
        }
        Ok(())
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex(&Sha256::digest(bytes)))
}
fn payload(bytes: &[u8], expected: &str) -> Result<()> {
    if bytes.is_empty()
        || bytes.len() > MAX_PAYLOAD
        || digest(bytes) != expected
        || validate_canonical_pc_cbor_bytes(bytes).is_err()
    {
        return Err("candidate bytes rejected");
    }
    Ok(())
}
fn named_digest(value: &str) -> Result<String> {
    let raw = value
        .strip_prefix("sha256:")
        .or_else(|| value.strip_prefix("0x"))
        .unwrap_or(value);
    if raw.len() != 64
        || !raw
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
    {
        return Err("candidate digest rejected");
    }
    Ok(format!("sha256:{raw}"))
}

pub(super) async fn read(pool: &PgPool, input: &Request, login: &str) -> Result<Value> {
    input.validate()?;
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| "candidate transaction unavailable")?;
    sqlx::query("set transaction isolation level repeatable read read only")
        .execute(&mut *tx)
        .await
        .map_err(|_| "candidate transaction rejected")?;
    for statement in [
        "set local row_security=on",
        "set local statement_timeout='8s'",
        "set local lock_timeout='3s'",
        "set local idle_in_transaction_session_timeout='10s'",
    ] {
        sqlx::query(statement)
            .execute(&mut *tx)
            .await
            .map_err(|_| "candidate bounds rejected")?;
    }
    let safe: bool=sqlx::query_scalar("select current_database()='openpc_candidate_index' and session_user=$1 and current_user=session_user
      and not r.rolsuper and not r.rolbypassrls and not r.rolcreaterole
      and pg_has_role(session_user,'openpc_candidate_index_reader','USAGE')
      and not exists(select 1 from pg_roles other where other.rolname in
       ('openpc_candidate_index_owner','openpc_candidate_index_maintenance','openpc_indexer_writer','openpc_indexer_manager','openpc_backup_operator')
       and pg_has_role(session_user,other.oid,'MEMBER'))
      and (select count(*)=10 and bool_and(c.relrowsecurity and c.relforcerowsecurity
        and pg_get_userbyid(c.relowner)='openpc_candidate_index_owner')
       from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='candidate'
        and c.relname in ('candidate_event','projection_generation','projection_profile','candidate_partition',
          'source_profile','source_publication','candidate_block','outbox_event','checkpoint','retained_candidate_identity'))
      from pg_roles r where r.rolname=session_user")
        .bind(login).fetch_one(&mut *tx).await.map_err(|_| "candidate role unavailable")?;
    if !safe {
        return Err("candidate role rejected");
    }
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-CANDIDATE_WRITE-V1',true),openpc.assert_request_context(false)")
        .bind(input.participant_id).bind(input.privacy_domain_id).bind(Uuid::now_v7())
        .execute(&mut *tx).await.map_err(|_| "candidate context rejected")?;
    // Only immutable source fields enter the archive. A historical reorg/fence
    // does not erase evidence and is never interpreted here as deletion consent.
    let rows=sqlx::query(r#"select e.payload_cbor,sp.source_profile_cbor,o.payload_cbor observed_cbor,o.payload_json observed_json,
      c.position_cbor,pub.publication_cbor,part.binding_cbor,pp.mapping_cbor,
      jsonb_build_object(
       'participantId',e.participant_id::text,'privacyDomainId',e.privacy_domain_id::text,
       'candidateId',e.candidate_event_id::text,'sourceProfileId',part.source_profile_id::text,
       'generationId',e.projection_generation_id::text,'partitionId',e.candidate_partition_id::text,
       'publicationDigest','sha256:'||encode(pub.publication_digest,'hex'),
       'sourceProfileDigest','sha256:'||encode(sp.source_profile_digest,'hex'),
       'partitionDigest','sha256:'||encode(part.binding_digest,'hex'),
       'projectionId',pp.projection_plan_id::text,'mappingDigest','sha256:'||encode(pp.mapping_digest,'hex'),
       'nativeRecordId',e.record_id,'recordKind',e.record_kind,'recordSequence',e.record_sequence::text,
       'candidateFeedSequence',o.aggregate_sequence::text,'observedEventId',o.event_id::text,
       'observedEventDigest','sha256:'||encode(o.payload_digest,'hex'),
       'payloadDigest','sha256:'||encode(e.payload_digest,'hex'),'payloadBytes',octet_length(e.payload_cbor),
       'schemaDigest','sha256:'||encode(e.schema_digest,'hex'),'evidenceDigest','sha256:'||encode(e.evidence_digest,'hex'),
       'checkpointDigest','sha256:'||encode(c.position_digest,'hex'),
       'occurredAt',to_char(e.observed_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
       'block',jsonb_build_object('number',b.block_number::text,'hash','sha256:'||encode(b.block_hash,'hex'),
        'parentHash','sha256:'||encode(b.parent_hash,'hex'),'finalityKind',b.finality_kind,
        'finalityEvidenceDigest','sha256:'||encode(b.finality_evidence_digest,'hex'),
        'headNumber',b.finality_head_number::text,'headHash',case when b.finality_head_hash is null then null else 'sha256:'||encode(b.finality_head_hash,'hex') end)) identity
      from candidate.candidate_event e
      join candidate.projection_generation gen using(participant_id,privacy_domain_id,projection_generation_id)
      join candidate.projection_profile pp using(participant_id,privacy_domain_id,projection_profile_id)
      join candidate.candidate_partition part on part.participant_id=e.participant_id and part.privacy_domain_id=e.privacy_domain_id
       and part.projection_generation_id=e.projection_generation_id and part.candidate_partition_id=e.candidate_partition_id
      join candidate.source_profile sp on sp.participant_id=e.participant_id and sp.privacy_domain_id=e.privacy_domain_id and sp.source_profile_id=part.source_profile_id
      join candidate.source_publication pub on pub.participant_id=e.participant_id and pub.privacy_domain_id=e.privacy_domain_id
       and pub.projection_generation_id=e.projection_generation_id
      join candidate.candidate_block b on b.participant_id=e.participant_id and b.privacy_domain_id=e.privacy_domain_id
       and b.projection_generation_id=e.projection_generation_id and b.candidate_partition_id=e.candidate_partition_id and b.candidate_block_id=e.candidate_block_id
      join candidate.outbox_event o on o.participant_id=e.participant_id and o.privacy_domain_id=e.privacy_domain_id
       and o.aggregate_type='candidate-partition' and o.aggregate_id=e.candidate_partition_id
       and o.event_type='io.openpc.indexer.projection.candidate.observed.v1'
       and o.payload_json->>'candidateId'='urn:openpc:candidate:'||e.candidate_event_id::text
      join candidate.checkpoint c on c.participant_id=e.participant_id and c.privacy_domain_id=e.privacy_domain_id
       and c.projection_generation_id=e.projection_generation_id and c.candidate_partition_id=e.candidate_partition_id
       and o.payload_json->>'sourceCursorDigest'='sha256:'||encode(c.position_digest,'hex')
      join candidate.retained_candidate_identity i on i.participant_id=e.participant_id and i.privacy_domain_id=e.privacy_domain_id and i.candidate_event_id=e.candidate_event_id
      where e.participant_id=$1 and e.privacy_domain_id=$2 and part.source_profile_id=$3
       and e.projection_generation_id=$4 and e.candidate_partition_id=$5 and e.candidate_event_id=$6
       and pp.source_profile_id=sp.source_profile_id and gen.source_profile_digest=sp.source_profile_digest
       and c.completed_at is not null and b.block_number between c.range_start and c.range_end
       and sha256(e.payload_cbor)=e.payload_digest and e.payload_digest=e.normalized_digest
       and i.payload_digest=e.payload_digest and i.payload_bytes=octet_length(e.payload_cbor)
       and i.projection_generation_id=e.projection_generation_id and i.record_id=e.record_id
       and i.original_identity->>'candidate_partition_id'=e.candidate_partition_id::text
       and sha256(sp.source_profile_cbor)=sp.source_profile_digest and sha256(pp.mapping_cbor)=pp.mapping_digest
       and sha256(part.binding_cbor)=part.binding_digest and sha256(pub.publication_cbor)=pub.publication_digest
       and sha256(c.position_cbor)=c.position_digest and sha256(o.payload_cbor)=o.payload_digest
       and o.payload_json->>'candidateDigest'='sha256:'||encode(e.normalized_digest,'hex')
       and o.payload_json->>'authority'='CANDIDATE_ONLY'
      limit 2"#)
        .bind(input.participant_id).bind(input.privacy_domain_id).bind(input.source_profile_id)
        .bind(input.generation_id).bind(input.partition_id).bind(input.candidate_id)
        .fetch_all(&mut *tx).await.map_err(|_| "candidate source unavailable")?;
    if rows.len() != 1 {
        return Err("candidate source cardinality rejected");
    }
    let row = &rows[0];
    let mut identity: Value = row
        .try_get("identity")
        .map_err(|_| "candidate identity unavailable")?;
    let bytes: Vec<u8> = row
        .try_get("payload_cbor")
        .map_err(|_| "candidate bytes unavailable")?;
    payload(
        &bytes,
        identity["payloadDigest"]
            .as_str()
            .ok_or("candidate digest unavailable")?,
    )?;
    for field in [
        "position_cbor",
        "publication_cbor",
        "binding_cbor",
        "mapping_cbor",
        "observed_cbor",
    ] {
        let bytes: Vec<u8> = row
            .try_get(field)
            .map_err(|_| "candidate lineage unavailable")?;
        validate_canonical_pc_cbor_bytes(&bytes).map_err(|_| "candidate lineage rejected")?;
    }
    let observed: Vec<u8> = row
        .try_get("observed_cbor")
        .map_err(|_| "candidate event unavailable")?;
    let decoded: Value =
        ciborium::de::from_reader(observed.as_slice()).map_err(|_| "candidate event rejected")?;
    let stored: Value = row
        .try_get("observed_json")
        .map_err(|_| "candidate event unavailable")?;
    if decoded != stored {
        return Err("candidate event binding rejected");
    }
    let profile_bytes: Vec<u8> = row
        .try_get("source_profile_cbor")
        .map_err(|_| "candidate profile unavailable")?;
    let profile = decode_client_indexer_profile_pc_cbor(&profile_bytes)
        .map_err(|_| "candidate profile rejected")?;
    if profile.participant_binding != input.participant_id.to_string()
        || profile.privacy_binding != input.privacy_domain_id.to_string()
    {
        return Err("candidate profile scope rejected");
    }
    identity["chainId"] = json!(profile.chain_id);
    identity["genesisDigest"] = json!(named_digest(&profile.genesis_hash)?);
    tx.rollback()
        .await
        .map_err(|_| "candidate snapshot close failed")?;
    Ok(
        json!({"version":"OPENPC_CANDIDATE_ARCHIVE_SOURCE_V1","authority":"NONE",
      "store":"openpc_candidate_index","class":"CANDIDATE_PROJECTION","identity":identity,"payloadHex":hex(&bytes)}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_canonical_bytes_are_required_through_the_full_store_limit() {
        // A canonical byte string whose total CBOR size is exactly the native cap.
        let mut bytes = vec![0x5a, 0x00, 0x0f, 0xff, 0xfb];
        bytes.resize(MAX_PAYLOAD, 0x42);
        assert!(payload(&bytes, &digest(&bytes)).is_ok());
        let mut changed = bytes.clone();
        changed[50] ^= 1;
        assert!(payload(&changed, &digest(&bytes)).is_err());
        bytes.push(0);
        assert!(payload(&bytes, &digest(&bytes)).is_err());
        for invalid in [
            vec![],
            vec![0x18, 0x01],
            vec![0xbf, 0xff],
            vec![0xa2, 0x01, 0x00, 0x01, 0x01],
        ] {
            assert!(payload(&invalid, &digest(&invalid)).is_err());
        }
    }
    #[test]
    fn request_rejects_duplicate_members_and_authority_or_connection_inputs() {
        let id = Uuid::now_v7();
        let text = format!(
            r#"{{"participantId":"{id}","privacyDomainId":"{id}","sourceProfileId":"{id}","generationId":"{id}","partitionId":"{id}","candidateId":"{id}"}}"#
        );
        assert!(
            serde_json::from_str::<Request>(&text)
                .unwrap()
                .validate()
                .is_ok()
        );
        for addition in [
            format!(r#", "candidateId":"{id}"}}"#),
            r#", "eligible":true}"#.into(),
            r#", "database":"other"}"#.into(),
        ] {
            let altered = text.trim_end_matches('}').to_owned() + &addition;
            assert!(serde_json::from_str::<Request>(&altered).is_err());
        }
    }
}
