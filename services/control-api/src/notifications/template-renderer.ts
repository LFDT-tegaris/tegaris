import { encodeEvidenceExportCompletedData } from '@openpc/security-kernel';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { notificationPayloadEncryptionProfile } from '../evidence/notification-payload-crypto.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import { parseEvidenceExportCompletedData } from './event-input.js';
import {
  validateNotificationRoutingInstallation,
  type NotificationRoutingInstallation,
} from './routing-installation-contract.js';

export class NotificationTemplateRenderError extends Error {
  constructor() {
    super('Notification template rendering unavailable');
  }
}

/** Pure rendering, never current routing or source authority. Trusted composition
 * calls this inside withCurrentNotificationRouting with its returned installation
 * and the source owner's validated completion data. Historical signed input alone
 * cannot admit an occurrence, unwrap a key, publish a payload or send a message.
 *
 * Plaintext bytes are canonical UTF-8 JSON containing exactly {body, subject}.
 * TEXT is literal; FIELD is a closed lookup, never interpolation, HTML, a URL
 * resolver, expression evaluation or property traversal. No normalization or
 * truncation may change the meaning of the authenticated template/source.
 */
export function renderEvidenceExportNotification(installation: unknown, source: unknown) {
  try {
    const { input } = validateNotificationRoutingInstallation(installation);
    const data = parseEvidenceExportCompletedData(immutableJsonCopy(source));
    const prefix = 'urn:openpc:resource:';
    if (!data.evidenceExportId.startsWith(prefix)) throw new Error();
    // The public parser owns wire types. The signed completion codec owns the
    // resource namespace and positive bounded count/checkpoint relationship.
    encodeEvidenceExportCompletedData({
      ...data,
      evidenceExportId: data.evidenceExportId.slice(prefix.length),
    });
    const render = (parts: NotificationRoutingInstallation['template']['body']) =>
      parts
        .map((part) => {
          const value = part.kind === 'TEXT' ? part.value : data[part.field];
          if (!value.isWellFormed()) throw new Error();
          return value;
        })
        .join('');
    // Installation validation owns the exact signed template and redaction
    // allowlist. Check the final header too, after all substitutions.
    const subject = render(input.template.subject);
    if (/[\r\n\u0085\u2028\u2029]/u.test(subject)) throw new Error();
    const body = render(input.template.body);
    const bytes = Buffer.from(canonicalJson({ body, subject }), 'utf8');
    if (bytes.length > notificationPayloadEncryptionProfile.maximumPlaintextBytes)
      throw new Error();
    return { subject, body, bytes, payloadDigest: sha256(bytes) };
  } catch {
    // Never include template, source, secret or provider values in diagnostics.
    throw new NotificationTemplateRenderError();
  }
}
