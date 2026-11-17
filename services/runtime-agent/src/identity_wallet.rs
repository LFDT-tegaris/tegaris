//! Wallet associations from the complete, signed Identity source projection.
//! Association and recovered possession are constraints, never invocation grants.
use crate::identity_source as source;
use openpc_multi_rpc::signed_transaction::SignedTransaction;
use pc_runtime_types::{RuntimeError, RuntimeResult};
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalletAssociation {
    id: String,
    epoch: u64,
    chain_id: u64,
    address: [u8; 20],
}
impl WalletAssociation {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

pub(super) struct WalletAssociations(Vec<WalletAssociation>);
impl WalletAssociations {
    pub fn parse(
        value: Option<&Value>,
        participant: &str,
        privacy: &str,
        principal: &str,
    ) -> RuntimeResult<Self> {
        // An older immutable snapshot provides no signer association.
        let Some(value) = value else {
            return Ok(Self(Vec::new()));
        };
        let records = value
            .as_array()
            .filter(|records| records.len() <= 4096)
            .ok_or(RuntimeError::InvalidInput)?;
        let mut ids = BTreeSet::new();
        let mut accounts = BTreeSet::new();
        let mut active = Vec::new();
        for record in records {
            let record = source::object(record)?;
            source::keys(
                record,
                &[
                    "wallet_binding_id",
                    "participant_id",
                    "privacy_domain_id",
                    "subject_id",
                    "chain_id",
                    "wallet_address",
                    "state",
                    "binding_epoch",
                    "row_version",
                ],
            )?;
            if source::string(record, "participant_id")? != participant
                || source::string(record, "privacy_domain_id")? != privacy
                || source::string(record, "subject_id")? != principal
            {
                return Err(RuntimeError::TargetIdentity);
            }
            let id = source::string(record, "wallet_binding_id")?.to_owned();
            let epoch = source::unsigned(record, "binding_epoch")?;
            let chain_id = source::unsigned(record, "chain_id")?;
            if epoch == 0
                || chain_id == 0
                || source::unsigned(record, "row_version")? != epoch
                || !ids.insert(id.clone())
            {
                return Err(RuntimeError::InvalidInput);
            }
            let text = source::string(record, "wallet_address")?;
            let hex = text.strip_prefix("0x").ok_or(RuntimeError::InvalidInput)?;
            if hex.len() != 40
                || !hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(RuntimeError::InvalidInput);
            }
            let mut address = [0; 20];
            for (i, byte) in address.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                    .map_err(|_| RuntimeError::InvalidInput)?;
            }
            match source::string(record, "state")? {
                "REVOKED" => {}
                "ACTIVE" => {
                    if !accounts.insert((chain_id, address)) {
                        return Err(RuntimeError::InvalidInput);
                    }
                    active.push(WalletAssociation {
                        id,
                        epoch,
                        chain_id,
                        address,
                    });
                }
                _ => return Err(RuntimeError::InvalidInput),
            }
        }
        Ok(Self(active))
    }

    pub fn for_transaction(
        &self,
        transaction: &SignedTransaction,
    ) -> RuntimeResult<WalletAssociation> {
        self.for_account(transaction.chain_id(), transaction.signer())
    }

    pub fn for_account(
        &self,
        chain_id: u64,
        address: &[u8; 20],
    ) -> RuntimeResult<WalletAssociation> {
        self.0
            .iter()
            .find(|binding| binding.chain_id == chain_id && &binding.address == address)
            .cloned()
            .ok_or(RuntimeError::Denied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn transaction() -> SignedTransaction {
        // Published EIP-155 signing example: independently known chain and signer.
        let raw = "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";
        let bytes: Vec<_> = (0..raw.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).unwrap())
            .collect();
        SignedTransaction::decode(&bytes).unwrap()
    }
    fn record() -> Value {
        json!({"wallet_binding_id":"binding", "participant_id":"participant", "privacy_domain_id":"privacy",
            "subject_id":"principal", "chain_id":"1", "wallet_address":"0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f",
            "state":"ACTIVE", "binding_epoch":"1", "row_version":"1"})
    }
    fn parse(value: &Value) -> RuntimeResult<WalletAssociations> {
        WalletAssociations::parse(Some(value), "participant", "privacy", "principal")
    }
    #[test]
    fn only_the_exact_active_chain_and_recovered_signer_match() {
        let transaction = transaction();
        let records = json!([record()]);
        let binding = parse(&records)
            .unwrap()
            .for_transaction(&transaction)
            .unwrap();
        assert_eq!(binding.id(), "binding");
        assert_eq!(binding.epoch(), 1);
        for (key, value) in [
            ("chain_id", json!("2")),
            (
                "wallet_address",
                json!("0x3535353535353535353535353535353535353535"),
            ),
            ("state", json!("REVOKED")),
        ] {
            let mut changed = records.clone();
            changed[0][key] = value;
            assert!(
                parse(&changed)
                    .unwrap()
                    .for_transaction(&transaction)
                    .is_err()
            );
        }
        assert!(
            WalletAssociations::parse(None, "participant", "privacy", "principal")
                .unwrap()
                .for_transaction(&transaction)
                .is_err()
        );
    }
    #[test]
    fn malformed_foreign_and_ambiguous_records_fail_closed() {
        for (key, value) in [
            ("participant_id", json!("foreign")),
            ("privacy_domain_id", json!("foreign")),
            ("subject_id", json!("foreign")),
            ("chain_id", json!("01")),
            ("chain_id", json!("0")),
            ("chain_id", json!("18446744073709551616")),
            ("binding_epoch", json!("0")),
            ("row_version", json!("2")),
            ("state", json!("PROPOSED")),
            (
                "wallet_address",
                json!("0x9D8A62F656A8D1615C1294FD71E9CFB3E4855A4F"),
            ),
            ("wallet_address", json!("0x00")),
            ("permissions", json!(["SIGNED_TRANSACTION_SUBMISSION"])),
        ] {
            let mut changed = record();
            changed[key] = value;
            assert!(parse(&json!([changed])).is_err(), "{key}");
        }
        assert!(parse(&json!([record(), record()])).is_err());
        let mut other = record();
        other["wallet_binding_id"] = json!("other");
        assert!(parse(&json!([record(), other])).is_err());
    }

    #[test]
    fn call_sender_cannot_borrow_a_wallet_from_another_chain_or_principal() {
        let signer = *transaction().signer();
        let active = parse(&json!([record()])).unwrap();
        assert_eq!(active.for_account(1, &signer).unwrap().id(), "binding");
        assert!(active.for_account(2, &signer).is_err());
        assert!(active.for_account(1, &[0x35; 20]).is_err());
        let mut revoked = record();
        revoked["state"] = json!("REVOKED");
        assert!(
            parse(&json!([revoked]))
                .unwrap()
                .for_account(1, &signer)
                .is_err()
        );
        let mut foreign = record();
        foreign["subject_id"] = json!("other-principal");
        assert!(parse(&json!([foreign])).is_err());
        assert!(
            WalletAssociations::parse(None, "participant", "privacy", "principal")
                .unwrap()
                .for_account(1, &signer)
                .is_err()
        );
    }
}
