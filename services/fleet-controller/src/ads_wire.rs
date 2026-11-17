//! Wire-compatible projections of Envoy v1.39.0 discovery.proto and base.proto.
//! https://github.com/envoyproxy/envoy/tree/v1.39.0/api/envoy/service/discovery/v3
//! Unknown optional Envoy metadata is not interpreted as OpenPC authority.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Node {
    #[prost(string, tag = "1")]
    pub id: String,
}
#[derive(Clone, PartialEq, prost::Message)]
pub struct RpcStatus {
    #[prost(int32, tag = "1")]
    pub code: i32,
    #[prost(string, tag = "2")]
    pub message: String,
    #[prost(message, repeated, tag = "3")]
    pub details: Vec<prost_types::Any>,
}
#[derive(Clone, PartialEq, prost::Message)]
pub struct ResourceLocator {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(map = "string,string", tag = "2")]
    pub dynamic_parameters: std::collections::HashMap<String, String>,
}
#[derive(Clone, PartialEq, prost::Message)]
pub struct DiscoveryRequest {
    #[prost(string, tag = "1")]
    pub version_info: String,
    #[prost(message, optional, tag = "2")]
    pub node: Option<Node>,
    #[prost(string, repeated, tag = "3")]
    pub resource_names: Vec<String>,
    #[prost(string, tag = "4")]
    pub type_url: String,
    #[prost(string, tag = "5")]
    pub response_nonce: String,
    #[prost(message, optional, tag = "6")]
    pub error_detail: Option<RpcStatus>,
    #[prost(message, repeated, tag = "7")]
    pub resource_locators: Vec<ResourceLocator>,
}
#[derive(Clone, PartialEq, prost::Message)]
pub struct DiscoveryResponse {
    #[prost(string, tag = "1")]
    pub version_info: String,
    #[prost(message, repeated, tag = "2")]
    pub resources: Vec<prost_types::Any>,
    #[prost(string, tag = "4")]
    pub type_url: String,
    #[prost(string, tag = "5")]
    pub nonce: String,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct ResourceName {
    #[prost(string, tag = "1")]
    pub name: String,
}
