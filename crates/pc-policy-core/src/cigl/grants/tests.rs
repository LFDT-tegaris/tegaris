use super::*;

struct Subjects {
    authenticated: bool,
}
impl CurrentInteractionSubjects for Subjects {
    fn participant_id(&self) -> &str {
        "participant"
    }
    fn privacy_domain_id(&self) -> &str {
        "privacy"
    }
    fn require_current(&self, now_ns: u64) -> RuntimeResult<()> {
        if self.authenticated && (10..20).contains(&now_ns) {
            Ok(())
        } else {
            Err(RuntimeError::ExpiredAuthorization)
        }
    }
    fn matches(&self, subject: &GrantSubject) -> RuntimeResult<bool> {
        Ok(match subject {
            GrantSubject::Role { id } => id == "role",
            GrantSubject::User { id } => id == "user",
            GrantSubject::Group { id } => id == "group",
            GrantSubject::Workload { id } => id == "workload",
            GrantSubject::Participant { id } => id == self.participant_id(),
            GrantSubject::AnyAuthenticated {} => self.authenticated,
        })
    }
}
fn grant(
    id: &str,
    interaction: &str,
    subject: GrantSubject,
    effect: GrantEffect,
) -> InteractionGrant {
    InteractionGrant {
        grant_id: id.into(),
        runtime_binding_id: interaction.into(),
        selector: [1; 4],
        subject,
        effect,
        surface: InteractionSurface::RawSubmission,
        status: GrantStatus::Active,
    }
}
fn set(grants: Vec<InteractionGrant>) -> InteractionGrantSet {
    InteractionGrantSet {
        profile_id: "profile".into(),
        profile_revision: 1,
        profile_digest: Digest::of("profile"),
        participant_id: "participant".into(),
        privacy_domain_id: "privacy".into(),
        status: GrantStatus::Active,
        grants,
    }
}
fn evaluate(
    set: &InteractionGrantSet,
    required: &[&str],
) -> RuntimeResult<Vec<MatchedInteraction>> {
    let digest = Digest::of("profile");
    let scope = GrantScope {
        profile_id: "profile",
        profile_revision: 1,
        profile_digest: &digest,
        participant_id: "participant",
        privacy_domain_id: "privacy",
        surface: InteractionSurface::RawSubmission,
    };
    set.match_required(
        &required.iter().map(|id| require(id)).collect::<Vec<_>>(),
        &scope,
        &Subjects {
            authenticated: true,
        },
        15,
    )
}
#[test]
fn every_required_frame_needs_allow_and_deny_wins_in_every_order() {
    let mut rows = vec![
        grant(
            "a",
            "first",
            GrantSubject::Role { id: "role".into() },
            GrantEffect::Allow,
        ),
        grant(
            "b",
            "second",
            GrantSubject::Group { id: "group".into() },
            GrantEffect::Allow,
        ),
    ];
    assert_eq!(
        evaluate(&set(rows.clone()), &["first", "second", "first"])
            .unwrap()
            .len(),
        3
    );
    assert!(evaluate(&set(rows.clone()), &["first", "third"]).is_err());
    rows.push(grant(
        "deny",
        "second",
        GrantSubject::AnyAuthenticated {},
        GrantEffect::Deny,
    ));
    assert!(matches!(
        evaluate(&set(rows.clone()), &["first", "second"]),
        Err(RuntimeError::Denied)
    ));
    rows.reverse();
    assert!(matches!(
        evaluate(&set(rows), &["second", "first"]),
        Err(RuntimeError::Denied)
    ));
}
#[test]
fn disabled_wrong_surface_and_cross_principal_rows_cannot_authorize() {
    let allow = grant(
        "a",
        "first",
        GrantSubject::Role { id: "role".into() },
        GrantEffect::Allow,
    );
    let mut row = allow.clone();
    row.status = GrantStatus::Disabled;
    assert!(evaluate(&set(vec![row]), &["first"]).is_err());
    let mut row = allow.clone();
    row.surface = InteractionSurface::EthCall;
    assert!(evaluate(&set(vec![row]), &["first"]).is_err());
    for subject in [
        GrantSubject::User { id: "role".into() },
        GrantSubject::Workload { id: "role".into() },
        GrantSubject::Group { id: "role".into() },
        GrantSubject::Participant { id: "role".into() },
    ] {
        let mut row = allow.clone();
        row.subject = subject;
        assert!(evaluate(&set(vec![row]), &["first"]).is_err());
    }
    let mut disabled_deny = allow.clone();
    disabled_deny.grant_id = "deny".into();
    disabled_deny.effect = GrantEffect::Deny;
    disabled_deny.status = GrantStatus::Disabled;
    assert!(evaluate(&set(vec![allow, disabled_deny]), &["first"]).is_ok());
}
#[test]
fn any_authenticated_is_explicit_and_cannot_resurrect_absent_or_stale_identity() {
    let set = set(vec![grant(
        "a",
        "first",
        GrantSubject::AnyAuthenticated {},
        GrantEffect::Allow,
    )]);
    let digest = Digest::of("profile");
    let scope = GrantScope {
        profile_id: "profile",
        profile_revision: 1,
        profile_digest: &digest,
        participant_id: "participant",
        privacy_domain_id: "privacy",
        surface: InteractionSurface::RawSubmission,
    };
    assert!(
        set.match_required(
            &[require("first")],
            &scope,
            &Subjects {
                authenticated: false
            },
            15
        )
        .is_err()
    );
    for now in [9, 20, u64::MAX] {
        assert!(
            set.match_required(
                &[require("first")],
                &scope,
                &Subjects {
                    authenticated: true
                },
                now
            )
            .is_err()
        );
    }
    for invalid in [
        r#"{"kind":"ANY_AUTHENTICATED","id":""}"#,
        r#"{"kind":"ROLE","id":"role","any":true}"#,
        r#"{"kind":"UNDEFINED"}"#,
    ] {
        assert!(
            serde_json::from_str::<GrantSubject>(invalid).is_err(),
            "{invalid}"
        );
    }
    let mut set = set;
    set.grants[0].subject = GrantSubject::Role { id: String::new() };
    assert!(evaluate(&set, &["first"]).is_err());
}
#[test]
fn stale_profile_foreign_tenant_disabled_profile_and_duplicate_ids_fail_closed() {
    let valid = set(vec![grant(
        "a",
        "first",
        GrantSubject::AnyAuthenticated {},
        GrantEffect::Allow,
    )]);
    let mut mutations = Vec::new();
    let mut set = valid.clone();
    set.participant_id = "foreign".into();
    mutations.push(set);
    let mut set = valid.clone();
    set.privacy_domain_id = "foreign".into();
    mutations.push(set);
    let mut set = valid.clone();
    set.profile_revision = 2;
    mutations.push(set);
    let mut set = valid.clone();
    set.profile_digest = Digest::of("changed");
    mutations.push(set);
    let mut set = valid.clone();
    set.status = GrantStatus::Disabled;
    mutations.push(set);
    let mut set = valid.clone();
    set.grants.push(set.grants[0].clone());
    mutations.push(set);
    for set in mutations {
        assert!(evaluate(&set, &["first"]).is_err());
    }
}

#[test]
fn unresolved_subject_owner_cannot_be_ignored_after_another_allow() {
    struct Unavailable;
    impl CurrentInteractionSubjects for Unavailable {
        fn participant_id(&self) -> &str {
            "participant"
        }
        fn privacy_domain_id(&self) -> &str {
            "privacy"
        }
        fn require_current(&self, _: u64) -> RuntimeResult<()> {
            Ok(())
        }
        fn matches(&self, subject: &GrantSubject) -> RuntimeResult<bool> {
            if matches!(subject, GrantSubject::Group { .. }) {
                Err(RuntimeError::RuntimeUnavailable)
            } else {
                Ok(true)
            }
        }
    }
    let set = set(vec![
        grant(
            "allow",
            "first",
            GrantSubject::AnyAuthenticated {},
            GrantEffect::Allow,
        ),
        grant(
            "unresolved",
            "first",
            GrantSubject::Group { id: "group".into() },
            GrantEffect::Deny,
        ),
    ]);
    let digest = Digest::of("profile");
    let scope = GrantScope {
        profile_id: "profile",
        profile_revision: 1,
        profile_digest: &digest,
        participant_id: "participant",
        privacy_domain_id: "privacy",
        surface: InteractionSurface::RawSubmission,
    };
    assert!(matches!(
        set.match_required(&[require("first")], &scope, &Unavailable, 15),
        Err(RuntimeError::RuntimeUnavailable)
    ));
}

fn require(id: &str) -> RequiredMethodInteraction<'_> {
    RequiredMethodInteraction {
        interaction_id: id,
        runtime_binding_id: id,
        selector: [1; 4],
    }
}

#[test]
fn shared_target_grants_cover_multiple_profile_edges_and_a_shared_deny_defeats_them() {
    let digest = Digest::of("profile");
    let scope = GrantScope {
        profile_id: "profile",
        profile_revision: 1,
        profile_digest: &digest,
        participant_id: "participant",
        privacy_domain_id: "privacy",
        surface: InteractionSurface::RawSubmission,
    };
    let required = [
        RequiredMethodInteraction {
            interaction_id: "path-one",
            runtime_binding_id: "shared-target",
            selector: [1; 4],
        },
        RequiredMethodInteraction {
            interaction_id: "path-two",
            runtime_binding_id: "shared-target",
            selector: [1; 4],
        },
    ];
    let mut snapshot = set(vec![grant(
        "shared",
        "shared-target",
        GrantSubject::AnyAuthenticated {},
        GrantEffect::Allow,
    )]);
    let matched = snapshot
        .match_required(
            &required,
            &scope,
            &Subjects {
                authenticated: true,
            },
            15,
        )
        .unwrap();
    assert_eq!(matched.len(), 2);
    assert_eq!(matched[0].grant_ids, matched[1].grant_ids);
    let mut other_selector = grant(
        "other-selector-deny",
        "shared-target",
        GrantSubject::AnyAuthenticated {},
        GrantEffect::Deny,
    );
    other_selector.selector = [2; 4];
    snapshot.grants.push(other_selector);
    assert!(
        snapshot
            .match_required(
                &required,
                &scope,
                &Subjects {
                    authenticated: true
                },
                15
            )
            .is_ok()
    );
    snapshot.grants.push(grant(
        "global-deny",
        "shared-target",
        GrantSubject::Role { id: "role".into() },
        GrantEffect::Deny,
    ));
    assert!(matches!(
        snapshot.match_required(
            &required,
            &scope,
            &Subjects {
                authenticated: true
            },
            15
        ),
        Err(RuntimeError::Denied)
    ));
}
