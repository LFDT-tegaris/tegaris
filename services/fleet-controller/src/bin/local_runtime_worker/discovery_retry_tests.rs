use super::*;
use std::{cell::Cell, cell::RefCell, future::ready};

fn aborted(stage: &'static str, code: &str) -> ObservationFailure {
    ObservationFailure {
        stage,
        sqlstate: Some(code.into()),
        attempt: 0,
    }
}

#[tokio::test]
async fn discovery_retry_rechecks_authority_after_completed_rollback() {
    let events = RefCell::new(Vec::new());
    let attempts = Cell::new(0);
    let result = observe_with_retry(
        1000,
        || {
            attempts.set(attempts.get() + 1);
            events.borrow_mut().push("authority");
            if attempts.get() == 1 {
                events.borrow_mut().push("rollback");
                ready(Err(aborted("connection", "40001")))
            } else {
                events.borrow_mut().push("commit");
                ready(Ok(()))
            }
        },
        || Some(0),
        |duration| {
            assert_eq!(duration, Duration::from_millis(25));
            events.borrow_mut().push("backoff");
            ready(())
        },
    )
    .await;
    assert!(result.is_ok());
    assert_eq!(attempts.get(), 2);
    assert_eq!(
        *events.borrow(),
        ["authority", "rollback", "backoff", "authority", "commit"]
    );
}

#[tokio::test]
async fn discovery_retry_exhausts_three_aborts_with_exact_delays() {
    let attempts = Cell::new(0);
    let delays = RefCell::new(Vec::new());
    let failure = observe_with_retry(
        1000,
        || {
            attempts.set(attempts.get() + 1);
            ready(Err(aborted("commit", "40001")))
        },
        || Some(0),
        |duration| {
            delays.borrow_mut().push(duration.as_millis());
            ready(())
        },
    )
    .await
    .unwrap_err();
    assert_eq!(attempts.get(), 3);
    assert_eq!(*delays.borrow(), [25, 75]);
    assert_eq!(failure.attempt, 3);
    assert_eq!(failure.stage, "commit");
    assert!(failure.retryable());
}

#[tokio::test]
async fn discovery_retry_never_repeats_denial_unknown_commit_or_failed_rollback() {
    for failure in [
        aborted("authority", "P0001"),
        aborted("authority", "42501"),
        aborted("rollback", "40001"),
        ObservationFailure::database(
            "commit",
            sqlx::Error::Io(std::io::ErrorKind::ConnectionReset.into()),
        ),
        ObservationFailure::terminal("context"),
    ] {
        let mut original = Some(failure);
        let result = observe_with_retry(
            1000,
            || ready(Err(original.take().expect("terminal failure was retried"))),
            || Some(0),
            |_| async { panic!("terminal failure must not back off") },
        )
        .await
        .unwrap_err();
        assert_eq!(result.attempt, 1);
        assert!(!result.retryable());
    }
}

#[tokio::test]
async fn discovery_retry_stops_when_certificate_expires_during_backoff() {
    let clock = Cell::new(0);
    let attempts = Cell::new(0);
    let result = observe_with_retry(
        25,
        || {
            attempts.set(attempts.get() + 1);
            ready(Err(aborted("connection", "40001")))
        },
        || Some(clock.get()),
        |duration| {
            clock.set(clock.get() + u64::try_from(duration.as_millis()).unwrap());
            ready(())
        },
    )
    .await
    .unwrap_err();
    assert_eq!(attempts.get(), 1);
    assert_eq!(result.stage, "certificate_validity");
    assert!(!result.retryable());
}

#[tokio::test]
async fn discovery_retry_stops_when_fresh_authority_check_denies_the_second_attempt() {
    let attempts = Cell::new(0);
    let result = observe_with_retry(
        1000,
        || {
            attempts.set(attempts.get() + 1);
            ready(Err(if attempts.get() == 1 {
                aborted("connection", "40001")
            } else {
                aborted("authority", "P0001")
            }))
        },
        || Some(0),
        |duration| {
            assert_eq!(duration, Duration::from_millis(25));
            ready(())
        },
    )
    .await
    .unwrap_err();
    assert_eq!(attempts.get(), 2);
    assert_eq!(result.stage, "authority");
    assert!(!result.retryable());
}

#[tokio::test]
async fn discovery_retry_rejects_expired_certificate_before_or_after_commit() {
    for expire_at_commit in [false, true] {
        let clock = Cell::new(if expire_at_commit { 0 } else { 100 });
        let attempts = Cell::new(0);
        let result = observe_with_retry(
            100,
            || {
                attempts.set(attempts.get() + 1);
                clock.set(100);
                ready(Ok(()))
            },
            || Some(clock.get()),
            |_| async { panic!("expiry must not back off") },
        )
        .await
        .unwrap_err();
        assert_eq!(attempts.get(), usize::from(expire_at_commit));
        assert_eq!(result.stage, "certificate_validity");
    }
}
