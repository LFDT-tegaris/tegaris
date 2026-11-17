use serde::{Deserialize, Serialize};

use crate::AuthorityDecision;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityContext {
    pub principal_id: String,
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub session_id: String,
    pub authority_envelope_id: String,
    pub authority_epoch: String,
    pub delegation_epoch: String,
    pub action_intent_id: String,
    pub policy_generation_digest: String,
    pub fact_generation_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityEvaluation {
    pub decision: AuthorityDecision,
    pub authorized: bool,
    pub terminal: bool,
    pub existence_visible: bool,
    pub payload_visible: bool,
    pub authority_context: AuthorityContext,
    pub inputs_digest: String,
    pub evaluated_at: String,
    pub explanation_codes: Vec<String>,
    pub trace_set_id: String,
}

impl AuthorityEvaluation {
    #[must_use]
    pub fn is_fail_closed(&self) -> bool {
        if self.decision.permits() {
            self.authorized && !self.terminal && self.existence_visible && self.payload_visible
        } else {
            !self.authorized && self.terminal && !self.existence_visible && !self.payload_visible
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthorityContext, AuthorityEvaluation};
    use crate::AuthorityDecision;

    fn context() -> AuthorityContext {
        AuthorityContext {
            principal_id: "principal-a".to_owned(),
            participant_id: "participant-a".to_owned(),
            privacy_domain_id: "privacy-a".to_owned(),
            session_id: "session-a".to_owned(),
            authority_envelope_id: "envelope-a".to_owned(),
            authority_epoch: "7".to_owned(),
            delegation_epoch: "3".to_owned(),
            action_intent_id: "ACT-POLICY_READ_EFFECTIVE_ACCESS-V1".to_owned(),
            policy_generation_digest: "sha256:policy".to_owned(),
            fact_generation_digest: "sha256:facts".to_owned(),
        }
    }

    #[test]
    fn permits_only_a_nonterminal_visible_allow() {
        let allow = AuthorityEvaluation {
            decision: AuthorityDecision::Allow,
            authorized: true,
            terminal: false,
            existence_visible: true,
            payload_visible: true,
            authority_context: context(),
            inputs_digest: "sha256:inputs".to_owned(),
            evaluated_at: "2026-08-28T00:00:00.000000Z".to_owned(),
            explanation_codes: vec!["EFFECTIVE_INTERSECTION_ALLOW".to_owned()],
            trace_set_id: "TS-ID-AUTHORIZATION".to_owned(),
        };
        assert!(allow.is_fail_closed());

        let leaking_deny = AuthorityEvaluation {
            decision: AuthorityDecision::Deny,
            authorized: false,
            terminal: true,
            existence_visible: true,
            payload_visible: false,
            ..allow
        };
        assert!(!leaking_deny.is_fail_closed());
    }
}
