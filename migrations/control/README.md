# Control-store migration ownership

`services/module-registry` owns control-store schema evolution. I09 does not hand-author SQL in this directory: a control-store change must originate in its Drizzle schema and use that service's `db:generate` command, committing the generated SQL and metadata unchanged. Fact and candidate-index migrations remain SQLx-owned in their respective lanes.

The I09 foundation records only the migration/restore boundary; no live migration is run or claimed here.
