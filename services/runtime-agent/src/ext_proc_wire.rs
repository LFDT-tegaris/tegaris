//! Envoy v1.39.0 external_processor.proto/base.proto wire projections.
//! https://github.com/envoyproxy/envoy/blob/v1.39.0/api/envoy/service/ext_proc/v3/external_processor.proto
#[derive(Clone, PartialEq, prost::Message)]
pub struct ProcessingRequest {
    #[prost(bool, tag = "10")]
    pub observability_mode: bool,
    #[prost(oneof = "RequestBody", tags = "2,3,4,5")]
    pub request: Option<RequestBody>,
}
#[derive(Clone, PartialEq, prost::Oneof)]
pub enum RequestBody {
    #[prost(message, tag = "2")]
    RequestHeaders(HttpHeaders),
    #[prost(message, tag = "3")]
    ResponseHeaders(HttpHeaders),
    #[prost(message, tag = "4")]
    RequestBody(HttpBody),
    #[prost(message, tag = "5")]
    ResponseBody(HttpBody),
}
#[derive(Clone, PartialEq, prost::Message)]
pub struct HttpHeaders {
    #[prost(message, optional, tag = "1")]
    pub headers: Option<HeaderMap>,
    #[prost(bool, tag = "3")]
    pub end_of_stream: bool,
}
#[derive(Clone, PartialEq, prost::Message)]
pub struct HeaderMap {
    #[prost(message, repeated, tag = "1")]
    pub headers: Vec<HeaderValue>,
}
#[derive(Clone, PartialEq, prost::Message)]
pub struct HeaderValue {
    #[prost(string, tag = "1")]
    pub key: String,
    #[prost(string, tag = "2")]
    pub value: String,
    #[prost(bytes = "vec", tag = "3")]
    pub raw_value: Vec<u8>,
}
#[derive(Clone, PartialEq, prost::Message)]
pub struct HttpBody {
    #[prost(bytes = "vec", tag = "1")]
    pub body: Vec<u8>,
    #[prost(bool, tag = "2")]
    pub end_of_stream: bool,
}
#[derive(Clone, PartialEq, prost::Message)]
pub struct ProcessingResponse {
    #[prost(oneof = "ResponseBody", tags = "1,2,3,4,7")]
    pub response: Option<ResponseBody>,
}
#[derive(Clone, PartialEq, prost::Oneof)]
pub enum ResponseBody {
    #[prost(message, tag = "1")]
    RequestHeaders(CommonWrapper),
    #[prost(message, tag = "2")]
    ResponseHeaders(CommonWrapper),
    #[prost(message, tag = "3")]
    RequestBody(CommonWrapper),
    #[prost(message, tag = "4")]
    ResponseBody(CommonWrapper),
    #[prost(message, tag = "7")]
    Immediate(ImmediateResponse),
}
#[derive(Clone, PartialEq, prost::Message)]
pub struct CommonWrapper {
    #[prost(message, optional, tag = "1")]
    pub response: Option<CommonResponse>,
}
#[derive(Clone, PartialEq, prost::Message)]
pub struct CommonResponse {
    #[prost(int32, tag = "1")]
    pub status: i32,
    #[prost(message, optional, tag = "2")]
    pub header_mutation: Option<HeaderMutation>,
    #[prost(message, optional, tag = "3")]
    pub body_mutation: Option<BodyMutation>,
}
#[derive(Clone, PartialEq, prost::Message)]
pub struct HeaderMutation {
    #[prost(message, repeated, tag = "1")]
    pub set_headers: Vec<HeaderValueOption>,
    #[prost(string, repeated, tag = "2")]
    pub remove_headers: Vec<String>,
}
#[derive(Clone, PartialEq, prost::Message)]
pub struct HeaderValueOption {
    #[prost(message, optional, tag = "1")]
    pub header: Option<HeaderValue>,
    #[prost(int32, tag = "3")]
    pub append_action: i32,
}
#[derive(Clone, PartialEq, prost::Message)]
pub struct BodyMutation {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub body: Option<Vec<u8>>,
}
#[derive(Clone, PartialEq, prost::Message)]
pub struct ImmediateResponse {
    #[prost(message, optional, tag = "1")]
    pub status: Option<HttpStatus>,
    #[prost(message, optional, tag = "2")]
    pub headers: Option<HeaderMutation>,
    #[prost(bytes = "vec", tag = "3")]
    pub body: Vec<u8>,
    #[prost(string, tag = "5")]
    pub details: String,
}
#[derive(Clone, PartialEq, prost::Message)]
pub struct HttpStatus {
    #[prost(int32, tag = "1")]
    pub code: i32,
}
