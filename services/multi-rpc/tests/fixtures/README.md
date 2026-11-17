# Provider header fixture

`synthetic-provider-header.json` is fabricated test input for the RPC header decoder and indexer response filter. Its hashes, address and transaction reference use repeated byte values; they do not identify a real block, account or transaction.

The fixture includes optional provider fields, a timestamp in seconds and a consistent millisecond timestamp. Tests verify field types, removal of provider-only extensions, preservation of permitted fields, rejection of unexpected payloads and mismatched block numbers, and stable normalization. Missing nullable fields are filled with null.

Passing these tests establishes response-shape behavior only. The fixture does not prove a block hash, canonical chain membership, execution, finality or compatibility with a particular live provider. Use separate authenticated provider and chain checks for those properties.
