//! Locally verified Ethereum transaction identity. Decoding proves the signer
//! and exact bytes; it does not grant workload, policy, provider or nonce authority.
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sha3::{Digest, Keccak256};

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("signed transaction rejected")]
pub struct TransactionError;
type Result<T> = std::result::Result<T, TransactionError>;

const MAX_BYTES: usize = 262_144;

mod unsigned;
pub use unsigned::UnsignedTransaction;

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FeeBumpIdentity {
    effect_digest: [u8; 32],
    maximum_fee: [u8; 32],
    maximum_priority_fee: [u8; 32],
}
impl FeeBumpIdentity {
    pub(crate) fn increases(&self, predecessor: &Self) -> bool {
        self.effect_digest == predecessor.effect_digest
            && self.maximum_fee > predecessor.maximum_fee
            && self.maximum_priority_fee > predecessor.maximum_priority_fee
    }
}

/// Fields cannot be constructed independently of the signed bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedTransaction {
    transaction: UnsignedTransaction,
    raw: Vec<u8>,
    hash: [u8; 32],
    signer: [u8; 20],
}

impl SignedTransaction {
    /// EIP-155, EIP-2930 and EIP-1559. Unprotected legacy signatures and
    /// unimplemented typed envelopes fail closed before any provider contact.
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.is_empty() || raw.len() > MAX_BYTES {
            return Err(TransactionError);
        }
        let (kind, encoded) = match raw[0] {
            1 | 2 => (raw[0], &raw[1..]),
            0xc0..=0xff => (0, raw),
            _ => return Err(TransactionError),
        };
        let root = Rlp::exact(encoded)?;
        let fields = root.list(12)?;
        let (signature_index, parity, preimage) = if kind == 0 {
            if fields.len() != 9 {
                return Err(TransactionError);
            }
            let v = fields[6].u64()?;
            if v < 37 {
                return Err(TransactionError);
            }
            let chain_id = (v - 35) / 2;
            let mut unsigned = fields[..6]
                .iter()
                .flat_map(|v| v.encoded.iter().copied())
                .collect::<Vec<_>>();
            unsigned.extend(rlp_integer(chain_id));
            unsigned.extend([0x80, 0x80]);
            (7, ((v - 35) % 2) as u8, rlp_list(&unsigned))
        } else {
            let count = if kind == 1 { 11 } else { 12 };
            if fields.len() != count {
                return Err(TransactionError);
            }
            let signature_index = count - 2;
            let parity = fields[count - 3].u64()?;
            if parity > 1 {
                return Err(TransactionError);
            }
            let unsigned = fields[..count - 3]
                .iter()
                .flat_map(|v| v.encoded.iter().copied())
                .collect::<Vec<_>>();
            let mut preimage = vec![kind];
            preimage.extend(rlp_list(&unsigned));
            (signature_index, parity as u8, preimage)
        };
        let transaction = UnsignedTransaction::decode(&preimage)?;
        let r = fields[signature_index].uint256()?;
        let s = fields[signature_index + 1].uint256()?;
        let signature = Signature::from_scalars(r, s).map_err(|_| TransactionError)?;
        // EIP-2 prohibits the alternate high-S representation.
        if signature.normalize_s() != signature {
            return Err(TransactionError);
        }
        let signing_hash = transaction.signing_hash();
        let recovered = VerifyingKey::recover_from_prehash(
            signing_hash,
            &signature,
            RecoveryId::try_from(parity).map_err(|_| TransactionError)?,
        )
        .map_err(|_| TransactionError)?;
        let public = recovered.to_sec1_point(false);
        let public_hash = Keccak256::digest(&public.as_bytes()[1..]);
        let mut signer = [0u8; 20];
        signer.copy_from_slice(&public_hash[12..]);
        Ok(Self {
            transaction,
            raw: raw.to_vec(),
            hash: Keccak256::digest(raw).into(),
            signer,
        })
    }
    /// The policy is supplied by admitted configuration, never from a request.
    /// Other authority, chain, target, preflight and nonce checks remain required.
    pub fn enforce_policy(
        &self,
        policy: &pc_policy_core::transaction_policy::TransactionPolicyV1,
    ) -> Result<()> {
        self.transaction.enforce_policy(policy)?;
        if self.raw.len() > policy.maximum_raw_transaction_bytes {
            return Err(TransactionError);
        }
        Ok(())
    }
    pub fn unsigned(&self) -> &UnsignedTransaction {
        &self.transaction
    }
    pub fn kind(&self) -> u8 {
        self.transaction.kind()
    }
    pub fn access_list_size(&self) -> (usize, usize) {
        self.transaction.access_list_size()
    }
    pub fn bytes(&self) -> &[u8] {
        &self.raw
    }
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }
    pub fn signer(&self) -> &[u8; 20] {
        &self.signer
    }
    pub fn chain_id(&self) -> u64 {
        self.transaction.chain_id()
    }
    pub fn nonce(&self) -> u64 {
        self.transaction.nonce()
    }
    pub fn destination(&self) -> Option<&[u8; 20]> {
        self.transaction.destination()
    }
    pub fn value(&self) -> &[u8; 32] {
        self.transaction.value()
    }
    pub fn gas_limit(&self) -> u64 {
        self.transaction.gas_limit()
    }
    pub fn maximum_fee(&self) -> &[u8; 32] {
        self.transaction.maximum_fee()
    }
    pub fn maximum_priority_fee(&self) -> &[u8; 32] {
        self.transaction.maximum_priority_fee()
    }
    pub fn signing_hash(&self) -> &[u8; 32] {
        self.transaction.signing_hash()
    }
    pub fn data(&self) -> &[u8] {
        self.transaction.data()
    }
    pub fn creation_address(&self) -> Result<[u8; 20]> {
        self.transaction.creation_address(&self.signer)
    }

    /// Internal simulation receives the complete verified signing preimage,
    /// including ordered/duplicate access-list entries. It cannot accept an
    /// actor's replacement call object or grant permission to disclose results.
    pub(crate) fn simulation_call(&self) -> Result<serde_json::Value> {
        self.transaction.simulation_call(&self.signer)
    }
}

pub fn create_address(creator: &[u8; 20], nonce: u64) -> [u8; 20] {
    let mut material = vec![0x94];
    material.extend(creator);
    material.extend(rlp_integer(nonce));
    Keccak256::digest(rlp_list(&material))[12..]
        .try_into()
        .expect("20 bytes")
}

pub fn create2_address(deployer: &[u8; 20], salt: &[u8; 32], init_code: &[u8]) -> Result<[u8; 20]> {
    if init_code.len() > MAX_BYTES {
        return Err(TransactionError);
    }
    let mut material = vec![0xff];
    material.extend(deployer);
    material.extend(salt);
    material.extend(Keccak256::digest(init_code));
    Ok(Keccak256::digest(material)[12..]
        .try_into()
        .expect("20 bytes"))
}

/// Bounded, canonical RLP views. No recursion or allocation from encoded lengths.
struct Rlp<'a> {
    encoded: &'a [u8],
    payload: &'a [u8],
    is_list: bool,
}
impl<'a> Rlp<'a> {
    fn item(input: &'a [u8]) -> Result<Self> {
        let prefix = *input.first().ok_or(TransactionError)?;
        let (header, length, is_list) = match prefix {
            0..=0x7f => (0, 1, false),
            0x80..=0xb7 => (1, usize::from(prefix - 0x80), false),
            0xc0..=0xf7 => (1, usize::from(prefix - 0xc0), true),
            _ => {
                let list = prefix >= 0xf8;
                let count = usize::from(prefix - if list { 0xf7 } else { 0xb7 });
                let bytes = input.get(1..1 + count).ok_or(TransactionError)?;
                if bytes[0] == 0 || count > std::mem::size_of::<usize>() {
                    return Err(TransactionError);
                }
                let mut length = 0usize;
                for byte in bytes {
                    length = length
                        .checked_mul(256)
                        .and_then(|v| v.checked_add(usize::from(*byte)))
                        .ok_or(TransactionError)?;
                }
                if length < 56 {
                    return Err(TransactionError);
                }
                (1 + count, length, list)
            }
        };
        let end = header.checked_add(length).ok_or(TransactionError)?;
        let encoded = input.get(..end).ok_or(TransactionError)?;
        let payload = &encoded[header..];
        if header == 1 && !is_list && length == 1 && payload[0] < 0x80 {
            return Err(TransactionError);
        }
        Ok(Self {
            encoded,
            payload,
            is_list,
        })
    }
    fn exact(input: &'a [u8]) -> Result<Self> {
        let value = Self::item(input)?;
        if value.encoded.len() != input.len() {
            return Err(TransactionError);
        }
        Ok(value)
    }
    fn bytes(&self) -> Result<&'a [u8]> {
        if self.is_list {
            Err(TransactionError)
        } else {
            Ok(self.payload)
        }
    }
    fn list(&self, limit: usize) -> Result<Vec<Self>> {
        if !self.is_list {
            return Err(TransactionError);
        }
        let mut remaining = self.payload;
        let mut fields = Vec::new();
        while !remaining.is_empty() {
            if fields.len() == limit {
                return Err(TransactionError);
            }
            let item = Self::item(remaining)?;
            remaining = &remaining[item.encoded.len()..];
            fields.push(item);
        }
        Ok(fields)
    }
    fn uint256(&self) -> Result<[u8; 32]> {
        let bytes = self.bytes()?;
        if bytes.len() > 32 || bytes.first() == Some(&0) {
            return Err(TransactionError);
        }
        let mut value = [0; 32];
        value[32 - bytes.len()..].copy_from_slice(bytes);
        Ok(value)
    }
    fn u64(&self) -> Result<u64> {
        let value = self.uint256()?;
        if value[..24] != [0; 24] {
            return Err(TransactionError);
        }
        Ok(u64::from_be_bytes(
            value[24..].try_into().expect("eight bytes"),
        ))
    }
}
fn validate_access_list(value: &Rlp<'_>) -> Result<(usize, usize)> {
    let entries = value.list(1024)?;
    let addresses = entries.len();
    let mut keys = 0;
    for entry in entries {
        let entry = entry.list(2)?;
        if entry.len() != 2 || entry[0].bytes()?.len() != 20 {
            return Err(TransactionError);
        }
        for key in entry[1].list(4096)? {
            if key.bytes()?.len() != 32 {
                return Err(TransactionError);
            }
            keys += 1;
        }
    }
    Ok((addresses, keys))
}
fn rlp_integer(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0x80];
    }
    let bytes = value.to_be_bytes();
    let index = bytes.iter().position(|b| *b != 0).expect("nonzero");
    if index == 7 && bytes[7] < 0x80 {
        return vec![bytes[7]];
    }
    let mut out = vec![0x80 + (8 - index) as u8];
    out.extend(&bytes[index..]);
    out
}
fn rlp_list(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if payload.len() < 56 {
        out.push(0xc0 + payload.len() as u8);
    } else {
        let bytes = payload.len().to_be_bytes();
        let start = bytes.iter().position(|b| *b != 0).expect("nonzero");
        out.push(0xf7 + (bytes.len() - start) as u8);
        out.extend(&bytes[start..]);
    }
    out.extend(payload);
    out
}

#[cfg(test)]
pub(crate) fn test_transaction(nonce: u64, fee: u64) -> SignedTransaction {
    test_transaction_with_calldata(nonce, fee, &[])
}

#[cfg(test)]
pub(crate) fn test_transaction_with_calldata(
    nonce: u64,
    fee: u64,
    data: &[u8],
) -> SignedTransaction {
    test_transaction_to(nonce, fee, Some([0x35; 20]), data)
}

#[cfg(test)]
pub(crate) fn test_transaction_to(
    nonce: u64,
    fee: u64,
    destination: Option<[u8; 20]>,
    data: &[u8],
) -> SignedTransaction {
    test_transaction_to_with_value(nonce, fee, destination, data, &[0; 32])
}

#[cfg(test)]
pub(crate) fn test_transaction_to_with_value(
    nonce: u64,
    fee: u64,
    destination: Option<[u8; 20]>,
    data: &[u8],
    value: &[u8; 32],
) -> SignedTransaction {
    test_transaction_with_fees(nonce, fee, 1, destination, data, value)
}

#[cfg(test)]
pub(crate) fn test_transaction_with_fees(
    nonce: u64,
    fee: u64,
    priority: u64,
    destination: Option<[u8; 20]>,
    data: &[u8],
    value: &[u8; 32],
) -> SignedTransaction {
    fn bytes(value: &[u8]) -> Vec<u8> {
        if value.len() == 1 && value[0] < 0x80 {
            return value.to_vec();
        }
        if value.len() < 56 {
            let mut encoded = vec![0x80 + value.len() as u8];
            encoded.extend(value);
            return encoded;
        }
        let size = value.len().to_be_bytes();
        let start = size.iter().position(|byte| *byte != 0).unwrap();
        let mut encoded = vec![0xb7 + (size.len() - start) as u8];
        encoded.extend(&size[start..]);
        encoded.extend(value);
        encoded
    }
    let key = k256::ecdsa::SigningKey::from_bytes((&[0x46; 32]).into()).unwrap();
    let mut fields = vec![1];
    fields.extend(rlp_integer(nonce));
    fields.extend(rlp_integer(priority));
    fields.extend(rlp_integer(fee));
    fields.extend(rlp_integer(100_000));
    fields.extend(bytes(
        destination
            .as_ref()
            .map_or(&[], |address| address.as_slice()),
    ));
    fields.extend(bytes(
        &value[value.iter().position(|byte| *byte != 0).unwrap_or(32)..],
    ));
    fields.extend(bytes(data));
    fields.push(0xc0);
    let mut unsigned = vec![2];
    unsigned.extend(rlp_list(&fields));
    let (signature, parity) = key.sign_prehash_recoverable(&Keccak256::digest(&unsigned));
    fields.extend(rlp_integer(u64::from(parity.to_byte())));
    for scalar in [signature.r().to_bytes(), signature.s().to_bytes()] {
        let start = scalar.iter().position(|b| *b != 0).unwrap();
        let scalar = &scalar[start..];
        if scalar.len() != 1 || scalar[0] >= 0x80 {
            fields.push(0x80 + scalar.len() as u8);
        }
        fields.extend(scalar);
    }
    let mut raw = vec![2];
    raw.extend(rlp_list(&fields));
    SignedTransaction::decode(&raw).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    // Independent published vector: https://eips.ethereum.org/EIPS/eip-155
    const EIP155: &str = "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";
    fn ceiling() -> pc_policy_core::transaction_policy::TransactionPolicyV1 {
        pc_policy_core::transaction_policy::TransactionPolicyV1 {
            version: 1,
            allowed_transaction_types: vec![0, 1, 2],
            maximum_value: [255; 32],
            maximum_gas_limit: u64::MAX,
            maximum_fee_per_gas: [255; 32],
            maximum_priority_fee_per_gas: [255; 32],
            maximum_raw_transaction_bytes: 131072,
            maximum_calldata_bytes: 32768,
            maximum_access_list_addresses: 128,
            maximum_access_list_storage_keys: 1024,
        }
    }
    #[test]
    fn transaction_policy_uses_signed_quantities_and_the_selected_fee_model() {
        let legacy = SignedTransaction::decode(&hex(EIP155)).unwrap();
        let mut policy = ceiling();
        policy.maximum_value = *legacy.value();
        policy.maximum_gas_limit = legacy.gas_limit();
        policy.maximum_fee_per_gas = *legacy.maximum_fee();
        policy.maximum_priority_fee_per_gas = [0; 32]; // Not an EIP-155 fee field.
        policy.maximum_raw_transaction_bytes = legacy.bytes().len();
        legacy.enforce_policy(&policy).unwrap();
        for mutate in [
            (|p: &mut pc_policy_core::transaction_policy::TransactionPolicyV1| {
                p.maximum_value = [0; 32]
            }) as fn(&mut pc_policy_core::transaction_policy::TransactionPolicyV1),
            |p| p.maximum_gas_limit -= 1,
            |p| p.maximum_fee_per_gas = [0; 32],
            |p| p.maximum_raw_transaction_bytes -= 1,
            |p| p.allowed_transaction_types = vec![1, 2],
        ] {
            let mut bad = policy.clone();
            mutate(&mut bad);
            assert!(legacy.enforce_policy(&bad).is_err());
        }
        let typed = test_transaction(9, 2);
        let mut policy = ceiling();
        policy.maximum_priority_fee_per_gas = [0; 32];
        assert!(typed.enforce_policy(&policy).is_err());
        policy.maximum_priority_fee_per_gas[31] = 1;
        typed.enforce_policy(&policy).unwrap();
    }
    #[test]
    fn transaction_policy_counts_the_total_signed_access_list_including_duplicates() {
        let key = k256::ecdsa::SigningKey::from_bytes((&[0x46; 32]).into()).unwrap();
        let mut access_list = Vec::new();
        for _ in 0..2 {
            let mut entry = vec![0x94];
            entry.extend([1; 20]);
            let mut keys = Vec::new();
            for _ in 0..3 {
                keys.push(0xa0);
                keys.extend([2; 32]);
            }
            entry.extend(rlp_list(&keys));
            access_list.extend(rlp_list(&entry));
        }
        let mut fields = vec![1, 9, 1];
        fields.extend(rlp_integer(100000));
        fields.push(0x94);
        fields.extend([0x35; 20]);
        fields.push(0x80);
        fields.extend([0x85, 1, 2, 3, 4, 5]);
        fields.extend(rlp_list(&access_list));
        let mut unsigned = vec![1];
        unsigned.extend(rlp_list(&fields));
        let (sig, parity) = key.sign_prehash_recoverable(&Keccak256::digest(&unsigned));
        fields.extend(rlp_integer(u64::from(parity.to_byte())));
        for scalar in [sig.r().to_bytes(), sig.s().to_bytes()] {
            let start = scalar.iter().position(|b| *b != 0).unwrap();
            let scalar = &scalar[start..];
            if scalar.len() != 1 || scalar[0] >= 0x80 {
                fields.push(0x80 + scalar.len() as u8);
            }
            fields.extend(scalar);
        }
        let mut raw = vec![1];
        raw.extend(rlp_list(&fields));
        let tx = SignedTransaction::decode(&raw).unwrap();
        assert_eq!(tx.kind(), 1);
        let prepared = UnsignedTransaction::decode(&unsigned).unwrap();
        assert!(prepared.matches_signed(tx.signer(), &tx));
        assert_eq!(prepared.bytes(), unsigned);
        assert_eq!(tx.access_list_size(), (2, 6));
        let call = tx.simulation_call().unwrap();
        assert_eq!(call["type"], "0x1");
        assert_eq!(call["gasPrice"], "0x1");
        assert!(call.get("maxFeePerGas").is_none());
        let entry = serde_json::json!({
            "address":format!("0x{}", "01".repeat(20)),
            "storageKeys":vec![format!("0x{}", "02".repeat(32));3],
        });
        assert_eq!(call["accessList"], serde_json::json!([entry, entry]));
        assert_eq!(call["data"], "0x0102030405");
        let mut policy = ceiling();
        policy.maximum_access_list_addresses = 2;
        policy.maximum_access_list_storage_keys = 6;
        policy.maximum_calldata_bytes = 5;
        tx.enforce_policy(&policy).unwrap();
        for mutate in [
            (|p: &mut pc_policy_core::transaction_policy::TransactionPolicyV1| {
                p.maximum_access_list_addresses = 1
            }) as fn(&mut pc_policy_core::transaction_policy::TransactionPolicyV1),
            |p| p.maximum_access_list_storage_keys = 5,
            |p| p.maximum_calldata_bytes = 4,
        ] {
            let mut bad = policy.clone();
            mutate(&mut bad);
            assert!(tx.enforce_policy(&bad).is_err());
        }
    }
    #[test]
    fn independent_legacy_signature_recovers_exact_owner_and_fields() {
        let tx = SignedTransaction::decode(&hex(EIP155)).unwrap();
        assert_eq!(tx.chain_id(), 1);
        assert_eq!(tx.nonce(), 9);
        assert_eq!(tx.gas_limit(), 21000);
        assert_eq!(tx.destination(), Some(&[0x35; 20]));
        assert_eq!(
            tx.signer().as_slice(),
            hex("9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f")
        );
        assert!(tx.data().is_empty());
        assert!(tx.creation_address().is_err());
        let call = tx.simulation_call().unwrap();
        assert_eq!(call["type"], "0x0");
        assert_eq!(call["gasPrice"], "0x4a817c800");
        assert_eq!(call["value"], "0xde0b6b3a7640000");
        assert!(call.get("accessList").is_none());
        assert!(call.get("maxFeePerGas").is_none());
    }
    #[test]
    fn unsigned_payloads_bind_exact_preimage_and_reject_signed_or_ambiguous_encoding() {
        let payload = hex(
            "ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080",
        );
        let prepared = UnsignedTransaction::decode(&payload).unwrap();
        let signed = SignedTransaction::decode(&hex(EIP155)).unwrap();
        assert!(prepared.matches_signed(signed.signer(), &signed));
        assert!(!prepared.matches_signed(&[1; 20], &signed));
        assert_eq!(prepared.bytes(), payload);
        assert_eq!(prepared.nonce(), 9);
        assert_eq!(prepared.gas_limit(), 21_000);
        assert_eq!(
            &prepared.value()[24..],
            &1_000_000_000_000_000_000u64.to_be_bytes()
        );
        assert!(UnsignedTransaction::decode(signed.bytes()).is_err());
        for index in [1, 3, 10, 20, 34, 40] {
            let mut altered = payload.clone();
            altered[index] ^= 1;
            if let Ok(altered) = UnsignedTransaction::decode(&altered) {
                assert!(!altered.matches_signed(signed.signer(), &signed));
            }
        }
        let mut trailing = payload.clone();
        trailing.push(0);
        assert!(UnsignedTransaction::decode(&trailing).is_err());
        for end in 0..payload.len() {
            assert!(UnsignedTransaction::decode(&payload[..end]).is_err());
        }
        let mut noncanonical = payload;
        noncanonical[0] += 1;
        noncanonical.insert(1, 0x81);
        assert!(UnsignedTransaction::decode(&noncanonical).is_err());
    }
    #[test]
    fn noncanonical_unprotected_truncated_and_unknown_transactions_fail_closed() {
        let raw = hex(EIP155);
        for end in 0..raw.len() {
            assert!(SignedTransaction::decode(&raw[..end]).is_err());
        }
        let mut trailing = raw.clone();
        trailing.push(0);
        assert!(SignedTransaction::decode(&trailing).is_err());
        for version in [0, 3, 4, 0x7f] {
            let mut bad = vec![version];
            bad.extend(&raw);
            assert!(SignedTransaction::decode(&bad).is_err());
        }
        let mut unprotected = raw.clone();
        unprotected[43] = 27;
        assert!(SignedTransaction::decode(&unprotected).is_err());
        for raw in [
            vec![0x81, 0x01],
            vec![0xb8, 1, 0x80],
            vec![0xf8, 0],
            vec![0xff; 9],
        ] {
            assert!(Rlp::exact(&raw).is_err());
        }
        assert!(Rlp::exact(&[0x00]).unwrap().u64().is_err());
    }
    #[test]
    fn published_create2_vectors_bind_deployer_salt_and_init_code() {
        // https://eips.ethereum.org/EIPS/eip-1014 examples 0, 3 and 6.
        for (code, expected) in [
            (vec![0], "4d1a2e2bb4f88f0250f26ffff098b0b30b26bf38"),
            (hex("deadbeef"), "70f2b2914a2a4b783faefb75f459a580616fcb5e"),
            (vec![], "e33c0c7f7df4809055c3eba6c09cfe4baf1bd9e0"),
        ] {
            assert_eq!(
                create2_address(&[0; 20], &[0; 32], &code)
                    .unwrap()
                    .as_slice(),
                hex(expected)
            );
        }
    }
    #[test]
    fn typed_signatures_bind_chain_nonce_destination_value_and_access_list() {
        let key = k256::ecdsa::SigningKey::from_bytes((&[0x46; 32]).into()).unwrap();
        for kind in [1u8, 2] {
            // Contract creation with a canonical empty access list.
            let mut fields = vec![1, 9, 1];
            if kind == 2 {
                fields.push(2);
            }
            fields.extend(rlp_integer(100_000));
            fields.extend([0x80, 0x80, 0x00, 0xc0]);
            let mut unsigned = vec![kind];
            unsigned.extend(rlp_list(&fields));
            let (sig, parity) = key.sign_prehash_recoverable(&Keccak256::digest(&unsigned));
            fields.extend(rlp_integer(u64::from(parity.to_byte())));
            for scalar in [sig.r().to_bytes(), sig.s().to_bytes()] {
                let start = scalar.iter().position(|b| *b != 0).unwrap();
                let scalar = &scalar[start..];
                if scalar.len() == 1 && scalar[0] < 0x80 {
                    fields.extend(scalar);
                } else {
                    fields.push(0x80 + scalar.len() as u8);
                    fields.extend(scalar);
                }
            }
            let mut raw = vec![kind];
            raw.extend(rlp_list(&fields));
            let tx = SignedTransaction::decode(&raw).unwrap();
            let prepared = UnsignedTransaction::decode(&unsigned).unwrap();
            assert!(prepared.matches_signed(tx.signer(), &tx));
            assert_eq!(
                prepared.creation_address(tx.signer()).unwrap(),
                tx.creation_address().unwrap()
            );
            assert!(UnsignedTransaction::decode(&raw).is_err());
            assert_eq!(
                tx.signer().as_slice(),
                hex("9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f")
            );
            assert_eq!(tx.chain_id(), 1);
            assert_eq!(tx.nonce(), 9);
            assert_eq!(tx.data(), [0]);
            assert_eq!(tx.gas_limit(), 100_000);
            assert_eq!(tx.maximum_fee()[31], if kind == 2 { 2 } else { 1 });
            assert_eq!(tx.maximum_priority_fee()[31], 1);
            assert_eq!(
                tx.signing_hash().as_slice(),
                Keccak256::digest(&unsigned).as_slice()
            );
            assert!(tx.creation_address().is_ok());
            let call = tx.simulation_call().unwrap();
            assert!(call.get("to").is_none());
            assert_eq!(call["nonce"], "0x9");
            assert_eq!(call["gas"], "0x186a0");
            assert_eq!(call["accessList"], serde_json::json!([]));
            if kind == 2 {
                assert_eq!(call["maxFeePerGas"], "0x2");
                assert_eq!(call["maxPriorityFeePerGas"], "0x1");
                assert!(call.get("gasPrice").is_none());
            }
            let mut changed = raw.clone();
            let index = raw.len() - fields.len();
            changed[index] = 2;
            let changed = SignedTransaction::decode(&changed).unwrap();
            assert_ne!(changed.signer(), tx.signer());
            assert_ne!(changed.hash(), tx.hash());
        }
    }
}
