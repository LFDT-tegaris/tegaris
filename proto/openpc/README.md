# OpenPC proto3/gRPC v1

These files are the versioned first-party network contract. Compile from `interfaces/proto` so imports resolve from that root. Every request is authenticated by mTLS workload identity plus the required metadata in `grpc-contract.yaml`; message fields never replace transport identity. All semantic signature preimages use PC-CBOR-1, and protobuf is a projection only.

`SafeProblemV1` is transported in trailing metadata key `openpc-problem-bin` when the caller is entitled to that detail. A status without this detail remains safe and non-leaking. Server-stream and bidirectional-stream reconnect starts from the caller's durable cursor or receipt ID and reauthorizes; it never assumes continuity from transport position.
