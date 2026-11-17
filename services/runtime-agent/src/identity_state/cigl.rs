//! Distinct CIGL subject resolution from the existing signed workload state and
//! verified mTLS peer. No request metadata supplies a role, group or user claim.
use super::*;
use pc_policy_core::cigl::grants::{CurrentInteractionSubjects, GrantSubject};

impl CurrentInteractionSubjects for WorkloadAuthorization {
    fn invocation_authorization(&self) -> RuntimeResult<&ValidatedInvocationAuthorization> {
        Ok(&self.authorization)
    }
    fn participant_id(&self) -> &str {
        &self.authorization.facts().participant_id
    }
    fn privacy_domain_id(&self) -> &str {
        &self.authorization.facts().privacy_domain_id
    }
    fn require_current(&self, now_ns: u64) -> RuntimeResult<()> {
        if now_ns < self.authorized_at_ns || now_ns >= self.valid_until_ns {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        Ok(())
    }
    fn matches(&self, subject: &GrantSubject) -> RuntimeResult<bool> {
        Ok(matches_workload(
            subject,
            self.authorization.facts(),
            &self.groups,
        ))
    }
}

fn matches_workload(
    subject: &GrantSubject,
    actor: &InvocationAuthorization,
    groups: &BTreeSet<String>,
) -> bool {
    match subject {
        GrantSubject::Role { id } => actor.roles.contains(id),
        // The mTLS workload cannot impersonate a User with an equal identifier.
        GrantSubject::User { .. } => false,
        GrantSubject::Group { id } => groups.contains(id),
        GrantSubject::Workload { id } => id == &actor.workload_id,
        GrantSubject::Participant { id } => id == &actor.participant_id,
        GrantSubject::AnyAuthenticated {} => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_kinds_do_not_alias_workload_principal_role_or_group_identifiers() {
        let actor = InvocationAuthorization {
            participant_id: "participant".into(),
            privacy_domain_id: "privacy".into(),
            workload_id: "workload".into(),
            actor_principal_id: "principal".into(),
            roles: vec!["role".into()],
            approval: None,
            webauthn: None,
        };
        let groups = BTreeSet::from(["group".into()]);
        for subject in [
            GrantSubject::Role { id: "role".into() },
            GrantSubject::Group { id: "group".into() },
            GrantSubject::Workload {
                id: "workload".into(),
            },
            GrantSubject::Participant {
                id: "participant".into(),
            },
            GrantSubject::AnyAuthenticated {},
        ] {
            assert!(matches_workload(&subject, &actor, &groups));
        }
        for subject in [
            GrantSubject::User {
                id: "principal".into(),
            },
            GrantSubject::User {
                id: "workload".into(),
            },
            GrantSubject::Group { id: "role".into() },
            GrantSubject::Role { id: "group".into() },
            GrantSubject::Participant {
                id: "principal".into(),
            },
            GrantSubject::Workload {
                id: "principal".into(),
            },
        ] {
            assert!(!matches_workload(&subject, &actor, &groups));
        }
        assert!(!matches_workload(
            &GrantSubject::Group { id: "group".into() },
            &actor,
            &BTreeSet::new()
        ));
    }
}
