//! Envoy v1.39.0 resource construction for the protected target's UDS path.
//! Field numbers follow the pinned Envoy API; typed extensions use TypedStruct.
use crate::REQUIRED_XDS_TYPES;
use pc_runtime_types::{RuntimeError, RuntimeResult};
use prost::Message;
use prost_types::{Any, Struct, Value, value::Kind};
use serde_json::json;
use std::{collections::BTreeMap, net::IpAddr};

#[derive(Clone, Copy)]
pub struct ProtectedListenerConfig<'a> {
    pub target_id: &'a str,
    pub capsule_id: &'a str,
    pub capsule_generation: u64,
    /// Qualified provider request budget. Preflight runs inside ext_proc and
    /// must receive this same finite envelope before Broker dispatch.
    pub request_timeout_ms: u64,
    /// Loopback for host tests or an unspecified address inside the isolated
    /// target network namespace. Arbitrary interface/DNS binding is rejected.
    pub bind_address: &'a str,
    pub port: u32,
    pub pds_socket: &'a str,
    pub broker_socket: &'a str,
    pub certificate_file: &'a str,
    pub private_key_file: &'a str,
    pub workload_ca_file: &'a str,
}
pub fn protected_resources(
    config: ProtectedListenerConfig<'_>,
) -> RuntimeResult<BTreeMap<String, Vec<Any>>> {
    let bind_address: IpAddr = config
        .bind_address
        .parse()
        .map_err(|_| RuntimeError::InvalidInput)?;
    if config.target_id.is_empty()
        || config.capsule_generation == 0
        || !(1..=60_000).contains(&config.request_timeout_ms)
        || config.capsule_id.is_empty()
        || config.capsule_id.len() > 160
        || !config
            .capsule_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:@/-".contains(&b))
        || config.port == 0
        || config.port > 65535
        || !(bind_address.is_loopback() || bind_address.is_unspecified())
        || [
            config.pds_socket,
            config.broker_socket,
            config.certificate_file,
            config.private_key_file,
            config.workload_ca_file,
        ]
        .iter()
        .any(|p| !p.starts_with('/') || p.contains(".."))
    {
        return Err(RuntimeError::InvalidInput);
    }
    let root = format!("openpc/{}/", config.target_id);
    let pds = format!("{root}pds");
    let broker = format!("{root}broker");
    let routes = format!("{root}routes");
    let secret = format!("{root}tls");
    let request_timeout = format!(
        "{}.{:03}s",
        config.request_timeout_ms / 1000,
        config.request_timeout_ms % 1000
    );
    let cluster = |name: &str, path: &str, http2: bool| -> RuntimeResult<Any> {
        let protocol = if http2 {
            BTreeMap::from([(
                "envoy.extensions.upstreams.http.v3.HttpProtocolOptions".into(),
                typed(
                    "envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
                    json!({"explicit_http_config":{"http2_protocol_options":{}}}),
                )?,
            )])
        } else {
            BTreeMap::new()
        };
        Ok(any(
            REQUIRED_XDS_TYPES[0],
            Cluster {
                name: name.into(),
                connect_timeout: Some(prost_types::Duration {
                    seconds: 1,
                    nanos: 0,
                }),
                load_assignment: Some(LoadAssignment {
                    cluster_name: name.into(),
                    endpoints: vec![LocalityEndpoints {
                        lb_endpoints: vec![LbEndpoint {
                            endpoint: Some(Endpoint {
                                address: Some(Address {
                                    socket_address: None,
                                    pipe: Some(Pipe { path: path.into() }),
                                }),
                            }),
                        }],
                    }],
                }),
                typed_extension_protocol_options: protocol,
            },
        ))
    };
    let hcm = typed(
        "envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
        json!({
            "stat_prefix":"protected_runtime","codec_type":"AUTO",
            "rds":{"route_config_name":routes,"config_source":{"ads":{},"resource_api_version":"V3"}},
            "forward_client_cert_details":"SANITIZE_SET","set_current_client_cert_details":{"cert":true,"uri":true},
            "normalize_path":true,"use_remote_address":true,"stream_idle_timeout":request_timeout,"request_timeout":request_timeout,
            "http_filters":[
                {"name":"envoy.filters.http.ext_proc","typed_config":{"@type":"type.googleapis.com/envoy.extensions.filters.http.ext_proc.v3.ExternalProcessor",
                    "grpc_service":{"envoy_grpc":{"cluster_name":pds,"authority":"pds.openpc.local"},
                        "initial_metadata":[{"key":"x-openpc-runtime-capsule-id","value":config.capsule_id},
                            {"key":"x-openpc-runtime-generation","value":config.capsule_generation.to_string()}]},"failure_mode_allow":false,"message_timeout":request_timeout,
                    "processing_mode":{"request_header_mode":"SEND","response_header_mode":"SEND","request_body_mode":"BUFFERED","response_body_mode":"BUFFERED"}}},
                {"name":"envoy.filters.http.router","typed_config":{"@type":"type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"}}
            ]
        }),
    )?;
    let tls = typed(
        "envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext",
        json!({
            "require_client_certificate":true,
            "common_tls_context":{"tls_params":{"tls_minimum_protocol_version":"TLSv1_3","tls_maximum_protocol_version":"TLSv1_3"},
                "tls_certificate_sds_secret_configs":[{"name":secret,"sds_config":{"ads":{},"resource_api_version":"V3"}}],
                "validation_context":{"trusted_ca":{"filename":config.workload_ca_file}}}
        }),
    )?;
    let listener = Listener {
        name: format!("{root}listener"),
        address: Some(Address {
            socket_address: Some(SocketAddress {
                address: bind_address.to_string(),
                port_value: config.port,
            }),
            pipe: None,
        }),
        filter_chains: vec![FilterChain {
            filters: vec![NetworkFilter {
                name: "envoy.filters.network.http_connection_manager".into(),
                typed_config: Some(hcm),
            }],
            transport_socket: Some(TransportSocket {
                name: "envoy.transport_sockets.tls".into(),
                typed_config: Some(tls),
            }),
        }],
    };
    let route = RouteConfiguration {
        name: routes,
        virtual_hosts: vec![VirtualHost {
            name: format!("{root}protected"),
            domains: vec!["*".into()],
            routes: vec![Route {
                r#match: Some(RouteMatch { prefix: "/".into() }),
                route: Some(RouteAction {
                    cluster: broker.clone(),
                    timeout: Some(prost_types::Duration {
                        seconds: (config.request_timeout_ms / 1000) as i64,
                        nanos: ((config.request_timeout_ms % 1000) * 1_000_000) as i32,
                    }),
                }),
            }],
        }],
    };
    let tls_secret = Secret {
        name: secret,
        tls_certificate: Some(TlsCertificate {
            certificate_chain: Some(DataSource {
                filename: config.certificate_file.into(),
            }),
            private_key: Some(DataSource {
                filename: config.private_key_file.into(),
            }),
        }),
    };
    Ok(BTreeMap::from([
        (
            REQUIRED_XDS_TYPES[0].into(),
            vec![
                cluster(&pds, config.pds_socket, true)?,
                cluster(&broker, config.broker_socket, false)?,
            ],
        ),
        (
            REQUIRED_XDS_TYPES[1].into(),
            vec![any(REQUIRED_XDS_TYPES[1], listener)],
        ),
        (
            REQUIRED_XDS_TYPES[2].into(),
            vec![any(REQUIRED_XDS_TYPES[2], route)],
        ),
        (
            REQUIRED_XDS_TYPES[3].into(),
            vec![any(REQUIRED_XDS_TYPES[3], tls_secret)],
        ),
    ]))
}
fn any(kind: &str, message: impl Message) -> Any {
    Any {
        type_url: kind.into(),
        value: message.encode_to_vec(),
    }
}
fn typed(kind: &str, value: serde_json::Value) -> RuntimeResult<Any> {
    let value = convert(value)?;
    let Some(Kind::StructValue(value)) = value.kind else {
        return Err(RuntimeError::InvalidInput);
    };
    Ok(any(
        "type.googleapis.com/xds.type.v3.TypedStruct",
        TypedStruct {
            type_url: format!("type.googleapis.com/{kind}"),
            value: Some(value),
        },
    ))
}
fn convert(value: serde_json::Value) -> RuntimeResult<Value> {
    Ok(Value {
        kind: Some(match value {
            serde_json::Value::Null => Kind::NullValue(0),
            serde_json::Value::Bool(v) => Kind::BoolValue(v),
            serde_json::Value::String(v) => Kind::StringValue(v),
            serde_json::Value::Number(v) => {
                Kind::NumberValue(v.as_f64().ok_or(RuntimeError::InvalidInput)?)
            }
            serde_json::Value::Array(v) => Kind::ListValue(prost_types::ListValue {
                values: v.into_iter().map(convert).collect::<RuntimeResult<_>>()?,
            }),
            serde_json::Value::Object(v) => Kind::StructValue(Struct {
                fields: v
                    .into_iter()
                    .map(|(k, v)| Ok((k, convert(v)?)))
                    .collect::<RuntimeResult<_>>()?,
            }),
        }),
    })
}
#[derive(Clone, PartialEq, Message)]
struct TypedStruct {
    #[prost(string, tag = "1")]
    type_url: String,
    #[prost(message, optional, tag = "2")]
    value: Option<Struct>,
}
#[derive(Clone, PartialEq, Message)]
struct Cluster {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(message, optional, tag = "4")]
    connect_timeout: Option<prost_types::Duration>,
    #[prost(message, optional, tag = "33")]
    load_assignment: Option<LoadAssignment>,
    #[prost(btree_map = "string,message", tag = "36")]
    typed_extension_protocol_options: BTreeMap<String, Any>,
}
#[derive(Clone, PartialEq, Message)]
struct LoadAssignment {
    #[prost(string, tag = "1")]
    cluster_name: String,
    #[prost(message, repeated, tag = "2")]
    endpoints: Vec<LocalityEndpoints>,
}
#[derive(Clone, PartialEq, Message)]
struct LocalityEndpoints {
    #[prost(message, repeated, tag = "2")]
    lb_endpoints: Vec<LbEndpoint>,
}
#[derive(Clone, PartialEq, Message)]
struct LbEndpoint {
    #[prost(message, optional, tag = "1")]
    endpoint: Option<Endpoint>,
}
#[derive(Clone, PartialEq, Message)]
struct Endpoint {
    #[prost(message, optional, tag = "1")]
    address: Option<Address>,
}
#[derive(Clone, PartialEq, Message)]
struct Address {
    #[prost(message, optional, tag = "1")]
    socket_address: Option<SocketAddress>,
    #[prost(message, optional, tag = "2")]
    pipe: Option<Pipe>,
}
#[derive(Clone, PartialEq, Message)]
struct SocketAddress {
    #[prost(string, tag = "2")]
    address: String,
    #[prost(uint32, tag = "3")]
    port_value: u32,
}
#[derive(Clone, PartialEq, Message)]
struct Pipe {
    #[prost(string, tag = "1")]
    path: String,
}
#[derive(Clone, PartialEq, Message)]
struct Listener {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(message, optional, tag = "2")]
    address: Option<Address>,
    #[prost(message, repeated, tag = "3")]
    filter_chains: Vec<FilterChain>,
}
#[derive(Clone, PartialEq, Message)]
struct FilterChain {
    #[prost(message, repeated, tag = "3")]
    filters: Vec<NetworkFilter>,
    #[prost(message, optional, tag = "6")]
    transport_socket: Option<TransportSocket>,
}
#[derive(Clone, PartialEq, Message)]
struct NetworkFilter {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(message, optional, tag = "4")]
    typed_config: Option<Any>,
}
#[derive(Clone, PartialEq, Message)]
struct TransportSocket {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(message, optional, tag = "3")]
    typed_config: Option<Any>,
}
#[derive(Clone, PartialEq, Message)]
struct RouteConfiguration {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(message, repeated, tag = "2")]
    virtual_hosts: Vec<VirtualHost>,
}
#[derive(Clone, PartialEq, Message)]
struct VirtualHost {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(string, repeated, tag = "2")]
    domains: Vec<String>,
    #[prost(message, repeated, tag = "3")]
    routes: Vec<Route>,
}
#[derive(Clone, PartialEq, Message)]
struct Route {
    #[prost(message, optional, tag = "1")]
    r#match: Option<RouteMatch>,
    #[prost(message, optional, tag = "2")]
    route: Option<RouteAction>,
}
#[derive(Clone, PartialEq, Message)]
struct RouteMatch {
    #[prost(string, tag = "1")]
    prefix: String,
}
#[derive(Clone, PartialEq, Message)]
struct RouteAction {
    #[prost(string, tag = "1")]
    cluster: String,
    #[prost(message, optional, tag = "8")]
    timeout: Option<prost_types::Duration>,
}
#[derive(Clone, PartialEq, Message)]
struct Secret {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(message, optional, tag = "2")]
    tls_certificate: Option<TlsCertificate>,
}
#[derive(Clone, PartialEq, Message)]
struct TlsCertificate {
    #[prost(message, optional, tag = "1")]
    certificate_chain: Option<DataSource>,
    #[prost(message, optional, tag = "2")]
    private_key: Option<DataSource>,
}
#[derive(Clone, PartialEq, Message)]
struct DataSource {
    #[prost(string, tag = "1")]
    filename: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_preflight_uses_the_qualified_request_budget_and_stays_fail_closed() {
        let mut config = ProtectedListenerConfig {
            target_id: "target-1",
            capsule_id: "capsule-1",
            capsule_generation: 1,
            request_timeout_ms: 5250,
            bind_address: "127.0.0.1",
            port: 8443,
            pds_socket: "/runtime/pds.sock",
            broker_socket: "/runtime/broker.sock",
            certificate_file: "/runtime/server.crt",
            private_key_file: "/runtime/server.key",
            workload_ca_file: "/runtime/ca.crt",
        };
        let resources = protected_resources(config).unwrap();
        let listener =
            Listener::decode(resources[REQUIRED_XDS_TYPES[1]][0].value.as_slice()).unwrap();
        let hcm = TypedStruct::decode(
            listener.filter_chains[0].filters[0]
                .typed_config
                .as_ref()
                .unwrap()
                .value
                .as_slice(),
        )
        .unwrap()
        .value
        .unwrap();
        let text = |value: &Value| match value.kind.as_ref().unwrap() {
            Kind::StringValue(value) => value.clone(),
            _ => panic!("expected string"),
        };
        assert_eq!(text(&hcm.fields["request_timeout"]), "5.250s");
        let Kind::ListValue(filters) = hcm.fields["http_filters"].kind.as_ref().unwrap() else {
            panic!("filters")
        };
        let Kind::StructValue(filter) = filters.values[0].kind.as_ref().unwrap() else {
            panic!("filter")
        };
        let Kind::StructValue(processor) = filter.fields["typed_config"].kind.as_ref().unwrap()
        else {
            panic!("processor")
        };
        assert_eq!(text(&processor.fields["message_timeout"]), "5.250s");
        assert_eq!(
            processor.fields["failure_mode_allow"].kind,
            Some(Kind::BoolValue(false))
        );
        let route =
            RouteConfiguration::decode(resources[REQUIRED_XDS_TYPES[2]][0].value.as_slice())
                .unwrap();
        assert_eq!(
            route.virtual_hosts[0].routes[0]
                .route
                .as_ref()
                .unwrap()
                .timeout,
            Some(prost_types::Duration {
                seconds: 5,
                nanos: 250_000_000
            })
        );
        for invalid in [0, 60_001, u64::MAX] {
            config.request_timeout_ms = invalid;
            assert!(protected_resources(config).is_err());
        }
    }
}
