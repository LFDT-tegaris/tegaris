# I09 foundation operating boundaries

The local foundation accepts only synthetic fixtures and versioned `secret://` references. It never contains a secret value, production endpoint, or authorization fallback. Startup must validate the selected profile, all signed qualification inputs, migration compatibility, and secret references before readiness. An invalid input leaves the prior accepted generation effective; no accepted generation means unready.

This foundation is deliberately not a production runbook: deployment, activation, live migration, and external acceptance remain gated. The integration runbook must add the authenticated operator/profile evidence and component-specific drills before it can make an operational claim.
