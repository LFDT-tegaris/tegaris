//! Process adapter for the policy service to call the fact owner's read-only
//! library. Connection and verification trust come from service configuration,
//! never from a simulation request.
use std::{
    fs,
    io::{self, BufRead, BufReader, Read, Write},
    sync::mpsc,
    time::{Duration, Instant},
};

use openpc_fact_service::{
    FactEvidenceLease, FactSignatureVerifier, PolicyFactLease, PolicyFactReader,
};
use serde::Deserialize;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Input {
    participant_id: String,
    privacy_domain_id: String,
    candidate_ids: Vec<String>,
    #[serde(default)]
    conditions: Vec<pc_policy_core::fact_condition::FactCondition>,
    #[serde(default)]
    workload_id: Option<String>,
}

async fn connect(
    max_connections: u32,
) -> Result<(sqlx::PgPool, FactSignatureVerifier), Box<dyn std::error::Error>> {
    let config = |key| std::env::var(key);
    let password = fs::read_to_string(config("POLICY_FACT_DATABASE_PASSWORD_FILE")?)?;
    let key = fs::read(config("POLICY_FACT_VERIFY_KEY_FILE")?)?;
    let key_id = config("POLICY_FACT_VERIFY_KEY_ID")?;
    let verifier = FactSignatureVerifier::from_key_identifier(&key_id, &key)?;
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .connect_with(
            PgConnectOptions::new()
                .host(&config("POLICY_FACT_DATABASE_HOST")?)
                .port(config("POLICY_FACT_DATABASE_PORT")?.parse()?)
                .database(&config("POLICY_FACT_DATABASE_NAME")?)
                .username(&config("POLICY_FACT_DATABASE_USER")?)
                .password(password.trim()),
        )
        .await?;
    Ok((pool, verifier))
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let (
        lease_mode,
        evidence_mode,
        evidence_lease_mode,
        retirement_preflight_mode,
        retirement_selection_mode,
    ) = match std::env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [] => (false, false, false, false, false),
        [mode] if mode == "--lease" => (true, false, false, false, false),
        [mode] if mode == "--evidence" => (false, true, false, false, false),
        [mode] if mode == "--evidence-lease" => (false, true, true, false, false),
        [mode] if mode == "--retirement-preflight" => (false, false, false, true, false),
        [mode] if mode == "--retirement-selection" => (false, false, false, false, true),
        _ => return Err("fact read mode rejected".into()),
    };
    let mut stdin = BufReader::new(io::stdin());
    let mut bytes = Vec::new();
    // Keep the existing read/evidence/lease bounds and protocols unchanged.
    let maximum = if retirement_preflight_mode {
        1_048_576
    } else {
        131_072
    };
    if lease_mode || evidence_lease_mode {
        stdin.by_ref().take(131_073).read_until(b'\n', &mut bytes)?;
        if bytes.last() != Some(&b'\n') {
            return Err("fact lease input rejected".into());
        }
    } else {
        stdin.by_ref().take(maximum + 1).read_to_end(&mut bytes)?;
    }
    if bytes.len() as u64 > maximum {
        return Err("fact read input too large".into());
    }
    if retirement_selection_mode {
        let request: openpc_fact_service::FactRetirementSelectionRequest =
            serde_json::from_slice(&bytes)?;
        request.validate()?;
        let (pool, verifier) = tokio::time::timeout(Duration::from_secs(5), connect(1)).await??;
        let result = PolicyFactReader::new(pool.clone(), verifier)
            .retirement_selection(&request)
            .await?;
        println!("{}", serde_json::to_string(&result)?);
        pool.close().await;
        return Ok(());
    }
    if retirement_preflight_mode {
        let request: openpc_fact_service::FactRetirementPreflightRequest =
            serde_json::from_slice(&bytes)?;
        request.validate()?;
        let (pool, verifier) = tokio::time::timeout(Duration::from_secs(5), connect(1)).await??;
        let result = PolicyFactReader::new(pool.clone(), verifier)
            .retirement_preflight(&request)
            .await?;
        println!("{}", serde_json::to_string(&result)?);
        pool.close().await;
        return Ok(());
    }
    if evidence_mode {
        let request: openpc_fact_service::FactEvidenceRequest = serde_json::from_slice(&bytes)?;
        let (pool, verifier) = connect(1).await?;
        let reader = PolicyFactReader::new(pool.clone(), verifier);
        if evidence_lease_mode {
            let lease = reader.evidence_lease(&request).await?;
            println!(
                "{}",
                serde_json::json!({"identity":"OPENPC-FACT-EVIDENCE-LEASE-1","batch":lease.batch(),"retirementBlocker":lease.blocker()})
            );
            io::stdout().flush()?;
            hold_lease(HeldLease::Evidence(lease), stdin, Instant::now()).await?;
        } else {
            let result = reader.evidence_batch(&request).await?;
            println!("{}", serde_json::to_string(&result)?);
        }
        pool.close().await;
        return Ok(());
    }
    let input: Input = serde_json::from_slice(&bytes)?;
    if input.candidate_ids.is_empty()
        || input.candidate_ids.len() > 256
        || [&input.participant_id, &input.privacy_domain_id]
            .into_iter()
            .chain(input.candidate_ids.iter())
            .any(|value| {
                value.is_empty()
                    || value.len() > 256
                    || !value.bytes().all(|byte| byte.is_ascii_graphic())
            })
    {
        return Err("fact read input rejected".into());
    }
    let (pool, verifier) = connect(if lease_mode { 2 } else { 1 }).await?;
    if input.conditions.len() > 16
        || input.conditions.iter().any(|condition| {
            condition.validate().is_err()
                || !input.candidate_ids.contains(&condition.fact().candidate_id)
        })
    {
        return Err("fact condition input rejected".into());
    }
    let reader = PolicyFactReader::new(pool.clone(), verifier.clone());
    // This is the same database mutation fence used by runtime release. Separate
    // reads below may borrow the second connection while this transaction lives.
    let mut lease = if lease_mode {
        Some(
            reader
                .lease_many(
                    &input.participant_id,
                    &input.privacy_domain_id,
                    &input.candidate_ids,
                    2000,
                )
                .await?
                .ok_or("fact lease unavailable")?,
        )
    } else {
        None
    };
    let lease_started = Instant::now();
    let mut snapshots = Vec::with_capacity(input.candidate_ids.len());
    for candidate in &input.candidate_ids {
        let snapshot = reader
            .read(&input.participant_id, &input.privacy_domain_id, candidate)
            .await?;
        let mut value = serde_json::to_value(&snapshot)?;
        let conditions = input
            .conditions
            .iter()
            .filter(|condition| &condition.fact().candidate_id == candidate)
            .collect::<Vec<_>>();
        if !value.is_null() && !conditions.is_empty() {
            let local = match reader
                .publication(
                    &input.participant_id,
                    &input.privacy_domain_id,
                    std::slice::from_ref(candidate),
                )
                .await?
            {
                Some((shard, _)) => Some(verifier.verify_local_facts(
                    &shard,
                    shard.local_content().ok_or("fact content unavailable")?,
                )?),
                None => None,
            };
            let results=conditions.into_iter().map(|condition| {
                let outcome=match (&local,&input.workload_id) {
                    (Some(local),Some(workload)) => local.evaluate_at_snapshot_anchor(condition,workload),
                    _ => pc_facts_core::RelationshipResult::Unresolved,
                };
                serde_json::json!({"conditionDigest":pc_runtime_types::Digest::of(pc_policy_core::pc_cbor_1(condition)),"workloadId":input.workload_id.as_deref().unwrap_or(""),"outcome":outcome})
            }).collect::<Vec<_>>();
            value["conditions"] = serde_json::to_value(results)?;
        }
        snapshots.push(value);
    }
    if let Some(lease) = &mut lease {
        lease.revalidate().await?;
        if lease_started.elapsed() >= Duration::from_secs(5) {
            return Err("fact lease expired".into());
        }
    }
    println!(
        "{}",
        serde_json::json!({"identity": if lease_mode { "OPENPC-FACT-OWNER-LEASE-1" } else { "OPENPC-FACT-OWNER-READ-1" }, "snapshots": snapshots})
    );
    io::stdout().flush()?;
    if let Some(lease) = lease {
        hold_lease(HeldLease::Policy(lease), stdin, lease_started).await?;
    }
    pool.close().await;
    Ok(())
}

enum HeldLease {
    Policy(PolicyFactLease),
    Evidence(FactEvidenceLease),
}

impl HeldLease {
    fn identity(&self) -> &'static str {
        match self {
            Self::Policy(_) => "OPENPC-FACT-OWNER-LEASE-1",
            Self::Evidence(_) => "OPENPC-FACT-EVIDENCE-LEASE-1",
        }
    }

    async fn revalidate(&mut self) -> Result<(), openpc_fact_service::FactStoreError> {
        match self {
            Self::Policy(lease) => lease.revalidate().await,
            Self::Evidence(lease) => lease.revalidate().await,
        }
    }

    async fn release(self) -> Result<(), openpc_fact_service::FactStoreError> {
        match self {
            Self::Policy(lease) => lease.release().await,
            Self::Evidence(lease) => lease.release().await,
        }
    }
}

async fn hold_lease(
    mut lease: HeldLease,
    mut stdin: BufReader<io::Stdin>,
    lease_started: Instant,
) -> Result<(), Box<dyn std::error::Error>> {
    let (send, receive) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        loop {
            let mut line = Vec::new();
            if stdin
                .by_ref()
                .take(33)
                .read_until(b'\n', &mut line)
                .is_err()
                || line.is_empty()
                || line.len() > 32
                || send.send(line).is_err()
            {
                break;
            }
        }
    });
    loop {
        let remaining = Duration::from_secs(5)
            .checked_sub(lease_started.elapsed())
            .ok_or("fact lease expired")?;
        let command = receive.recv_timeout(remaining)?;
        match command.as_slice() {
            b"CHECK\n" => {
                lease.revalidate().await?;
                if lease_started.elapsed() >= Duration::from_secs(5) {
                    return Err("fact lease expired".into());
                }
                println!(
                    "{}",
                    serde_json::json!({"identity":lease.identity(),"state":"HELD"})
                );
                io::stdout().flush()?;
            }
            b"RELEASE\n" => {
                lease.release().await?;
                break;
            }
            _ => return Err("fact lease command rejected".into()),
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("fact owner read unavailable");
        std::process::exit(1);
    }
}
