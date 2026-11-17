# Policy control-store migrations

This directory is owned exclusively by `services/module-registry` and Drizzle
Kit. Change the owning Drizzle schema and run that package's unmodified
`db:generate` command to produce SQL migrations and metadata. Never append,
rewrite, or hand-edit generated SQL.

Local PostgreSQL grants and non-bypass test setup belong to registered I03
fixtures, not this generated migration boundary.
