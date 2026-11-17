//! Only a confirmed database abort may repeat a discovery observation.
use std::{future::Future, time::Duration};

#[derive(Debug)]
pub(super) struct ObservationFailure {
    pub stage: &'static str,
    pub sqlstate: Option<String>,
    pub attempt: usize,
}

impl ObservationFailure {
    pub fn terminal(stage: &'static str) -> Self {
        Self {
            stage,
            sqlstate: None,
            attempt: 0,
        }
    }

    pub fn database(stage: &'static str, error: sqlx::Error) -> Self {
        Self {
            stage,
            sqlstate: error
                .as_database_error()
                .and_then(|error| error.code())
                .map(|code| code.into_owned()),
            attempt: 0,
        }
    }

    pub fn retryable(&self) -> bool {
        self.stage != "rollback" && self.sqlstate.as_deref() == Some("40001")
    }
}

pub(super) async fn observe_with_retry<Observe, Observation, Clock, Pause, Delay>(
    certificate_until_ms: u64,
    mut observe: Observe,
    mut clock: Clock,
    mut pause: Pause,
) -> Result<(), ObservationFailure>
where
    Observe: FnMut() -> Observation,
    Observation: Future<Output = Result<(), ObservationFailure>>,
    Clock: FnMut() -> Option<u64>,
    Pause: FnMut(Duration) -> Delay,
    Delay: Future<Output = ()>,
{
    for attempt in 1..=3 {
        let current = clock().ok_or_else(|| ObservationFailure {
            attempt,
            ..ObservationFailure::terminal("clock")
        })?;
        if current >= certificate_until_ms {
            return Err(ObservationFailure {
                attempt,
                ..ObservationFailure::terminal("certificate_validity")
            });
        }
        // Each attempt finishes rollback (or commits) before returning. No
        // activation, ACK or signed runtime effect occurs in this transaction.
        match observe().await {
            Ok(()) => {
                let current = clock().ok_or_else(|| ObservationFailure {
                    attempt,
                    ..ObservationFailure::terminal("clock")
                })?;
                if current < certificate_until_ms {
                    return Ok(());
                }
                return Err(ObservationFailure {
                    attempt,
                    ..ObservationFailure::terminal("certificate_validity")
                });
            }
            Err(mut error) => {
                error.attempt = attempt;
                if !error.retryable() || attempt == 3 {
                    return Err(error);
                }
                pause(Duration::from_millis(if attempt == 1 { 25 } else { 75 })).await;
            }
        }
    }
    unreachable!("the third observation attempt is terminal")
}

#[cfg(test)]
#[path = "discovery_retry_tests.rs"]
mod tests;
