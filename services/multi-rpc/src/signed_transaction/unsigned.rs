//! Exact EIP-155/2930/1559 signing payloads. Sender ownership is a separate
//! identity check; an unsigned payload carries no signature or authority.
use super::{
    Keccak256, MAX_BYTES, Result, Rlp, TransactionError, create_address, validate_access_list,
};
use sha3::Digest;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsignedTransaction {
    kind: u8,
    payload: Vec<u8>,
    signing_hash: [u8; 32],
    chain_id: u64,
    nonce: u64,
    destination: Option<[u8; 20]>,
    value: [u8; 32],
    gas_limit: u64,
    maximum_fee: [u8; 32],
    maximum_priority_fee: [u8; 32],
    data: Vec<u8>,
    access_list_addresses: usize,
    access_list_storage_keys: usize,
}

impl UnsignedTransaction {
    /// Decode the actual bytes to be signed, including ordered access lists.
    /// Legacy payloads require the EIP-155 chain id and two empty suffixes.
    /// Signed envelopes, unprotected legacy, trailing data and alternate RLP
    /// encodings are rejected instead of normalized into a different payload.
    pub fn decode(payload: &[u8]) -> Result<Self> {
        if payload.is_empty() || payload.len() > MAX_BYTES {
            return Err(TransactionError);
        }
        let (kind, encoded) = match payload[0] {
            1 | 2 => (payload[0], &payload[1..]),
            0xc0..=0xff => (0, payload),
            _ => return Err(TransactionError),
        };
        let fields = Rlp::exact(encoded)?.list(9)?;
        let (chain_id, nonce_index, gas_index, access_list) = if kind == 0 {
            if fields.len() != 9 || !fields[7].bytes()?.is_empty() || !fields[8].bytes()?.is_empty()
            {
                return Err(TransactionError);
            }
            (fields[6].u64()?, 0, 2, (0, 0))
        } else {
            let count = if kind == 1 { 8 } else { 9 };
            if fields.len() != count {
                return Err(TransactionError);
            }
            (
                fields[0].u64()?,
                1,
                3 + usize::from(kind == 2),
                validate_access_list(&fields[count - 1])?,
            )
        };
        let maximum_fee = fields[gas_index - 1].uint256()?;
        let maximum_priority_fee = if kind == 2 {
            fields[2].uint256()?
        } else {
            maximum_fee
        };
        let gas_limit = fields[gas_index].u64()?;
        if chain_id == 0 || gas_limit == 0 || maximum_priority_fee > maximum_fee {
            return Err(TransactionError);
        }
        let to = fields[gas_index + 1].bytes()?;
        let destination = if to.is_empty() {
            None
        } else {
            Some(to.try_into().map_err(|_| TransactionError)?)
        };
        Ok(Self {
            kind,
            payload: payload.to_vec(),
            signing_hash: Keccak256::digest(payload).into(),
            chain_id,
            nonce: fields[nonce_index].u64()?,
            destination,
            value: fields[gas_index + 2].uint256()?,
            gas_limit,
            maximum_fee,
            maximum_priority_fee,
            data: fields[gas_index + 3].bytes()?.to_vec(),
            access_list_addresses: access_list.0,
            access_list_storage_keys: access_list.1,
        })
    }

    pub fn enforce_policy(
        &self,
        policy: &pc_policy_core::transaction_policy::TransactionPolicyV1,
    ) -> Result<()> {
        policy.validate().map_err(|_| TransactionError)?;
        if !policy.allowed_transaction_types.contains(&self.kind)
            || self.value > policy.maximum_value
            || self.gas_limit > policy.maximum_gas_limit
            || self.maximum_fee > policy.maximum_fee_per_gas
            || (self.kind == 2 && self.maximum_priority_fee > policy.maximum_priority_fee_per_gas)
            || self.payload.len() > policy.maximum_raw_transaction_bytes
            || self.data.len() > policy.maximum_calldata_bytes
            || self.access_list_addresses > policy.maximum_access_list_addresses
            || self.access_list_storage_keys > policy.maximum_access_list_storage_keys
        {
            return Err(TransactionError);
        }
        Ok(())
    }

    /// Exact payload equality and recovered sender binding are both required.
    /// This is an identity check, never a current-authority or send decision.
    pub fn matches_signed(&self, sender: &[u8; 20], signed: &super::SignedTransaction) -> bool {
        self == signed.unsigned() && sender == signed.signer()
    }

    pub fn validate_fee_bump(
        &self,
        sender: &[u8; 20],
        signed: &super::SignedTransaction,
    ) -> Result<()> {
        if sender != signed.signer()
            || !signed
                .unsigned()
                .fee_bump_identity()?
                .increases(&self.fee_bump_identity()?)
        {
            return Err(TransactionError);
        }
        Ok(())
    }

    /// Hash every canonical signing field except the applicable fee fields.
    /// Ordered access-list entries, duplicates, gas and transaction type remain
    /// exact; storing this digest avoids retaining calldata in the journal.
    pub(crate) fn fee_bump_identity(&self) -> Result<super::FeeBumpIdentity> {
        let encoded = if self.kind == 0 {
            &self.payload[..]
        } else {
            &self.payload[1..]
        };
        let fields = Rlp::exact(encoded)?.list(9)?;
        let mut material = b"openpc:transaction-fee-bump-effect:v1".to_vec();
        material.push(self.kind);
        for (index, field) in fields.iter().enumerate() {
            let is_fee = match self.kind {
                0 => index == 1,
                1 => index == 2,
                2 => index == 2 || index == 3,
                _ => return Err(TransactionError),
            };
            if !is_fee {
                material.extend(field.encoded);
            }
        }
        Ok(super::FeeBumpIdentity {
            effect_digest: Keccak256::digest(material).into(),
            maximum_fee: self.maximum_fee,
            maximum_priority_fee: self.maximum_priority_fee,
        })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.payload
    }
    pub fn signing_hash(&self) -> &[u8; 32] {
        &self.signing_hash
    }
    pub fn kind(&self) -> u8 {
        self.kind
    }
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }
    pub fn nonce(&self) -> u64 {
        self.nonce
    }
    pub fn gas_limit(&self) -> u64 {
        self.gas_limit
    }
    pub fn destination(&self) -> Option<&[u8; 20]> {
        self.destination.as_ref()
    }
    pub fn value(&self) -> &[u8; 32] {
        &self.value
    }
    pub fn maximum_fee(&self) -> &[u8; 32] {
        &self.maximum_fee
    }
    pub fn maximum_priority_fee(&self) -> &[u8; 32] {
        &self.maximum_priority_fee
    }
    pub fn data(&self) -> &[u8] {
        &self.data
    }
    pub fn access_list_size(&self) -> (usize, usize) {
        (self.access_list_addresses, self.access_list_storage_keys)
    }
    pub fn creation_address(&self, sender: &[u8; 20]) -> Result<[u8; 20]> {
        if self.destination.is_some() {
            return Err(TransactionError);
        }
        Ok(create_address(sender, self.nonce))
    }

    pub(super) fn simulation_call(&self, sender: &[u8; 20]) -> Result<serde_json::Value> {
        use serde_json::json;
        fn hex(bytes: &[u8]) -> String {
            format!(
                "0x{}",
                bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
            )
        }
        let quantity = |word: &[u8; 32]| {
            let text = hex(word);
            let significant = text[2..].trim_start_matches('0');
            if significant.is_empty() {
                "0x0".to_owned()
            } else {
                format!("0x{significant}")
            }
        };
        let mut call = json!({
            "from":hex(sender), "chainId":format!("0x{:x}",self.chain_id),
            "type":format!("0x{:x}",self.kind), "nonce":format!("0x{:x}",self.nonce),
            "gas":format!("0x{:x}",self.gas_limit), "value":quantity(&self.value), "data":hex(&self.data)
        });
        if let Some(to) = self.destination {
            call["to"] = json!(hex(&to));
        }
        if self.kind == 2 {
            call["maxFeePerGas"] = json!(quantity(&self.maximum_fee));
            call["maxPriorityFeePerGas"] = json!(quantity(&self.maximum_priority_fee));
        } else {
            call["gasPrice"] = json!(quantity(&self.maximum_fee));
        }
        if self.kind != 0 {
            let fields = Rlp::exact(&self.payload[1..])?.list(9)?;
            let mut entries = Vec::new();
            for entry in fields[if self.kind == 2 { 8 } else { 7 }].list(1024)? {
                let pair = entry.list(2)?;
                let keys = pair[1]
                    .list(4096)?
                    .iter()
                    .map(|key| key.bytes().map(hex))
                    .collect::<Result<Vec<_>>>()?;
                entries.push(json!({"address":hex(pair[0].bytes()?),"storageKeys":keys}));
            }
            call["accessList"] = json!(entries);
        }
        Ok(call)
    }
}

#[cfg(test)]
mod fee_bump_tests {
    use super::super::{rlp_integer, rlp_list};
    use super::*;

    fn encoded(kind: u8, fields: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = if kind == 0 { vec![] } else { vec![kind] };
        bytes.extend(rlp_list(&fields.concat()));
        bytes
    }

    #[test]
    fn fee_bump_preserves_every_non_fee_field_and_ordered_access_list() {
        for kind in 0..=2 {
            let mut destination = vec![0x94];
            destination.extend([0x35; 20]);
            let mut address = vec![0x94];
            address.extend([0x36; 20]);
            let mut key = vec![0xa0];
            key.extend([1; 32]);
            let mut entry = address;
            entry.extend(rlp_list(&[key.clone(), key].concat()));
            let access = rlp_list(&rlp_list(&entry));
            let fields = match kind {
                0 => vec![
                    rlp_integer(9),
                    vec![2],
                    rlp_integer(100_000),
                    destination,
                    vec![0x80],
                    vec![0x80],
                    vec![1],
                    vec![0x80],
                    vec![0x80],
                ],
                1 => vec![
                    vec![1],
                    rlp_integer(9),
                    vec![2],
                    rlp_integer(100_000),
                    destination,
                    vec![0x80],
                    vec![0x80],
                    access,
                ],
                _ => vec![
                    vec![1],
                    rlp_integer(9),
                    vec![1],
                    vec![2],
                    rlp_integer(100_000),
                    destination,
                    vec![0x80],
                    vec![0x80],
                    access,
                ],
            };
            let old = UnsignedTransaction::decode(&encoded(kind, &fields))
                .unwrap()
                .fee_bump_identity()
                .unwrap();
            let fees: &[usize] = match kind {
                0 => &[1],
                1 => &[2],
                _ => &[2, 3],
            };
            let mut bumped = fields.clone();
            for fee in fees {
                bumped[*fee] = vec![4];
            }
            let new = UnsignedTransaction::decode(&encoded(kind, &bumped))
                .unwrap()
                .fee_bump_identity()
                .unwrap();
            assert!(new.increases(&old));
            for index in 0..fields.len() {
                if fees.contains(&index) || (kind == 0 && index >= 7) {
                    continue;
                }
                let mut changed = bumped.clone();
                let is_to = index
                    == match kind {
                        0 => 3,
                        1 => 4,
                        _ => 5,
                    };
                let is_access = kind != 0 && index == fields.len() - 1;
                changed[index] = if is_to {
                    let mut to = vec![0x94];
                    to.extend([0x37; 20]);
                    to
                } else if is_access {
                    vec![0xc0]
                } else {
                    vec![3]
                };
                let changed = UnsignedTransaction::decode(&encoded(kind, &changed))
                    .unwrap()
                    .fee_bump_identity()
                    .unwrap();
                assert!(!changed.increases(&old), "kind {kind}, field {index}");
            }
        }
    }
}
