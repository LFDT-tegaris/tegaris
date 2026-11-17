# Local secrets

The supported [local runner](../README.md) generates the complete synthetic secret,
signing-key and certificate set beneath its private external run root. It mounts
only the selected service's required files read-only and retains the intended
non-root container access. The Compose `secrets` section is the mount catalogue;
the runner owns generation and the corresponding service configuration.

Do not generate a partial set here or copy values into `.env.example`,
`connection.env.example`, source control or logs. This checked-in directory is
only a fallback path for explicitly configured local use; it contains no usable
credentials. Retained environments keep their own secret root and ownership
marker. Keep those credentials with their original environment and use the
supported OIDC/WebAuthn flow for human authentication.

## File ownership and service access

Keep each environment's secret directory outside the source checkout and accessible only to its operator and intended service identities. A container receives only the files required for its role. Do not make an entire secret directory world-readable to resolve a mount or ownership error; inspect the affected service's configured UID, mount and file permissions.

A private key, a public verification certificate and a secret reference have different roles. A checked-in public certificate is not a credential for a current deployment. Do not import historical verification fixtures as an active trust root without the deployment's supported trust-establishment procedure.

## Retention, renewal and recovery

Stopping a retained environment preserves its data, keys and identity. Store any backup according to the [operations guide](../../../../docs/operations/README.md), including the consistency requirements between identity material and durable records.

Track internal certificates separately from public HTTPS. The local fixture uses short-lived internal certificates; renewing a reverse-proxy certificate does not renew service certificates or business authority. Use the relevant owner to issue replacement material and verify the resulting authenticated behavior. Do not edit retained validity timestamps, replace an issuer independently or bypass certificate validation.

If a secret is missing or a certificate has expired, preserve the original environment and diagnose its owner and supported recovery path. Copying material from a different environment does not restore the original identity.

## Reports and contributions

Do not attach secret directories, browser profiles, raw environment dumps or complete diagnostic archives to issues. Include the affected service, safe error code, source revision and redacted file-role information. Report suspected credential disclosure through [SECURITY.md](../../../../SECURITY.md).
