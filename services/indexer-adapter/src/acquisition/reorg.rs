//! Detect a changed predecessor before admitting any record from a later batch.
use super::*;
use crate::ReorgInvalidation;

pub(super) async fn invalidate_changed_tail(
    store: &CandidateStore,
    source: &mut Source<'_>,
    job: &AcquisitionBatch,
    tail: &[(u64, String, String)],
    first: &SourceBlockHeader,
) -> Result<bool, CandidateStoreError> {
    let Some((end, old_hash, _)) = tail.first() else {
        return Ok(false);
    };
    if first.parent_hash == *old_hash {
        return Ok(false);
    }
    let mut child = (
        first.number,
        first.parent_hash.clone(),
        first.timestamp_seconds,
    );
    let mut changed = None;
    let mut exchanges = Vec::new();
    for (number, hash, parent) in tail {
        if number.checked_add(1) != Some(child.0) {
            return Err(CandidateStoreError::InvalidBatch);
        }
        let read = source.read(*number, true).await?;
        let observed = SourceBlockHeader::decode(&read.value["result"], *number)
            .map_err(|_| CandidateStoreError::InvalidBatch)?;
        if child.1 != observed.hash || child.2 < observed.timestamp_seconds {
            return Err(CandidateStoreError::InvalidBatch);
        }
        if observed.hash == *hash {
            break;
        }
        // A transient or internally inconsistent response cannot invalidate history.
        let again = source.read(*number, true).await?;
        if read.value["result"] != again.value["result"] {
            return Err(CandidateStoreError::InvalidBatch);
        }
        exchanges.extend([read.evidence, again.evidence]);
        let common_parent = observed.parent_hash == *parent;
        child = (
            observed.number,
            observed.parent_hash.clone(),
            observed.timestamp_seconds,
        );
        changed = Some(((*number, hash.clone()), observed));
        if common_parent {
            break;
        }
    }
    let Some((old, observed)) = changed else {
        return Err(CandidateStoreError::InvalidBatch);
    };
    let evidence = digest_hex(&canonical_cbor(&json!({
        "purpose":"openpc:acquired-chain-reorg:v1","publicationDigest":crate::store::sha_digest(&source.inputs.published().publication_digest),
        "oldBlock":old,"newBlockHash":observed.hash,"affectedEnd":end,"sourceExchanges":exchanges,
    })));
    let invalidation =
        ReorgInvalidation::from_acquisition(source.inputs, job, old, &observed, *end, evidence)?;
    store.invalidate_reorg(&invalidation).await?;
    Ok(true)
}
