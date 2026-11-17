//! Exact bounded ABI values for independently observed state projections.
//! Validate the complete layout before allocating decoded values: aliased tails,
//! hidden padding, gaps, backwards offsets and trailing bytes are not projections.
use super::*;

pub fn decode_canonical_abi(types: &[AbiType], data: &[u8]) -> RuntimeResult<Vec<ArgumentValue>> {
    if data.len() > 131072
        || !data.len().is_multiple_of(WORD)
        || types.len() > MAX_DECODED_COLLECTION
    {
        return Err(RuntimeError::InvalidInput);
    }
    for abi in types {
        validate_abi_type(abi, 0)?;
    }
    let mut budget = 65536;
    if sequence_end(types, data, 0, &mut budget)? != data.len() {
        return Err(RuntimeError::InvalidInput);
    }
    decode_sequence(types, data, 0)
}

fn sequence_end(
    types: &[AbiType],
    data: &[u8],
    base: usize,
    budget: &mut usize,
) -> RuntimeResult<usize> {
    if types.len() > MAX_DECODED_COLLECTION {
        return Err(RuntimeError::InvalidInput);
    }
    let head_size = types.iter().try_fold(0usize, |size, abi| {
        size.checked_add(if is_dynamic(abi) {
            WORD
        } else {
            static_size(abi)?
        })
        .ok_or(RuntimeError::InvalidInput)
    })?;
    let mut tail = base
        .checked_add(head_size)
        .filter(|end| *end <= data.len())
        .ok_or(RuntimeError::InvalidInput)?;
    let mut head = base;
    for abi in types {
        if is_dynamic(abi) {
            if usize_word(data, head)? != tail - base {
                return Err(RuntimeError::InvalidInput);
            }
            tail = value_end(abi, data, tail, budget)?;
            head += WORD;
        } else {
            head = value_end(abi, data, head, budget)?;
        }
    }
    Ok(tail)
}
fn value_end(
    abi: &AbiType,
    data: &[u8],
    offset: usize,
    budget: &mut usize,
) -> RuntimeResult<usize> {
    *budget = budget.checked_sub(1).ok_or(RuntimeError::BudgetExhausted)?;
    match abi {
        AbiType::Bytes | AbiType::String => {
            let length = usize_word(data, offset)?;
            if length > MAX_DECODED_COLLECTION * WORD {
                return Err(RuntimeError::InvalidInput);
            }
            let start = offset.checked_add(WORD).ok_or(RuntimeError::InvalidInput)?;
            let actual_end = start
                .checked_add(length)
                .ok_or(RuntimeError::InvalidInput)?;
            let end = actual_end
                .checked_add((WORD - length % WORD) % WORD)
                .ok_or(RuntimeError::InvalidInput)?;
            let padding = data
                .get(actual_end..end)
                .ok_or(RuntimeError::InvalidInput)?;
            if padding.iter().any(|byte| *byte != 0) {
                return Err(RuntimeError::InvalidInput);
            }
            Ok(end)
        }
        AbiType::Array { element, length } => {
            let (count, base) = match length {
                Some(count) => (*count, offset),
                None => (
                    usize_word(data, offset)?,
                    offset.checked_add(WORD).ok_or(RuntimeError::InvalidInput)?,
                ),
            };
            if count > MAX_DECODED_COLLECTION || count > *budget {
                return Err(RuntimeError::BudgetExhausted);
            }
            sequence_end(&vec![(**element).clone(); count], data, base, budget)
        }
        AbiType::Tuple(fields) => sequence_end(fields, data, offset, budget),
        _ => {
            word(data, offset)?;
            offset.checked_add(WORD).ok_or(RuntimeError::InvalidInput)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn words(values: &[u64]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value| {
                let mut word = [0; 32];
                word[24..].copy_from_slice(&value.to_be_bytes());
                word
            })
            .collect()
    }
    #[test]
    fn exact_projection_decodes_typed_scalars_and_ordered_dynamic_tails() {
        assert_eq!(
            decode_canonical_abi(&[AbiType::Uint(256), AbiType::Bool], &words(&[4660, 1])).unwrap(),
            vec![ArgumentValue::uint(4660), ArgumentValue::Bool(true)]
        );
        let types = [
            AbiType::String,
            AbiType::Array {
                element: Box::new(AbiType::Uint(256)),
                length: None,
            },
        ];
        let mut encoded = words(&[64, 128, 3]);
        let mut text = [0u8; 32];
        text[..3].copy_from_slice(b"abc");
        encoded.extend(text);
        encoded.extend(words(&[2, 7, 8]));
        assert_eq!(
            decode_canonical_abi(&types, &encoded).unwrap(),
            vec![
                ArgumentValue::String("abc".into()),
                ArgumentValue::Array(vec![ArgumentValue::uint(7), ArgumentValue::uint(8)])
            ]
        );
        let mut padding = encoded.clone();
        padding[127] = 1;
        assert!(decode_canonical_abi(&types, &padding).is_err());
        let mut aliased = encoded.clone();
        aliased[63] = 64;
        assert!(decode_canonical_abi(&types, &aliased).is_err());
        let mut gap = encoded.clone();
        gap[31] = 96;
        assert!(decode_canonical_abi(&types, &gap).is_err());
        encoded.extend([0; 32]);
        assert!(decode_canonical_abi(&types, &encoded).is_err());
    }
    #[test]
    fn nested_tuple_arrays_use_their_own_offset_base_and_reject_trailing_or_invalid_words() {
        let types = [AbiType::Tuple(vec![
            AbiType::Uint(8),
            AbiType::Array {
                element: Box::new(AbiType::String),
                length: Some(1),
            },
        ])];
        let mut encoded = words(&[32, 5, 64, 32, 1]);
        let mut text = [0u8; 32];
        text[0] = b'x';
        encoded.extend(text);
        assert_eq!(
            decode_canonical_abi(&types, &encoded).unwrap(),
            vec![ArgumentValue::Tuple(vec![
                ArgumentValue::uint(5),
                ArgumentValue::Array(vec![ArgumentValue::String("x".into())])
            ])]
        );
        assert!(decode_canonical_abi(&[AbiType::Bool], &words(&[2])).is_err());
        assert!(decode_canonical_abi(&[AbiType::Uint(8)], &words(&[256])).is_err());
        assert!(decode_canonical_abi(&[AbiType::Uint(256)], &words(&[1, 2])).is_err());
        assert!(decode_canonical_abi(&[], &words(&[0])).is_err());
        assert!(decode_canonical_abi(&[AbiType::String], &words(&[0, 0])).is_err());
    }
}
