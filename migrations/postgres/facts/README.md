# Fact and candidate-index PostgreSQL migration boundary

`STORE-FACT-PG` and `STORE-CANDIDATE-INDEX-PG` are SQLx-owned, SQL-first Rust migration lanes. Drizzle and hand-authored control-store generation do not own this directory.

I05 Gate3 instantiates the local PostgreSQL 18.6 Fact Bridge integrity schema
without giving candidate storage semantic authority. The migration persists the
exact schema tuple, canonical payload, purpose-bound COSE Sign1 and finality
inputs, and independently guards verified-shard readiness plus reorg
predecessor/replacement linkage. Production migration, activation,
external-indexer qualification, certified signing, and provider acceptance
remain `NOT_PROVEN_OPEN`.
