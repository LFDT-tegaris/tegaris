use super::{ConnectionError, now_ms};
use reqwest::Url;
use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
};

/// Configuration input from the routing owner, not an HTTP request context.
/// Deliberately has no Debug implementation: endpoint details are restricted.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointDescriptor {
    pub endpoint_id: String,
    pub normalized_uri: String,
    pub reference_identity: String,
    pub port: u16,
    pub path: String,
    pub dns_policy_ref: String,
    pub tls_policy_ref: String,
    pub credential_ref: String,
    pub egress_policy_ref: String,
    pub endpoint_generation: u64,
}

#[derive(Clone)]
pub struct NetworkRange {
    address: IpAddr,
    prefix: u8,
}
impl NetworkRange {
    pub fn parse(value: &str) -> Result<Self, ConnectionError> {
        let (address, prefix) = value.split_once('/').ok_or(ConnectionError::Destination)?;
        let address: IpAddr = address.parse().map_err(|_| ConnectionError::Destination)?;
        let prefix: u8 = prefix.parse().map_err(|_| ConnectionError::Destination)?;
        let range = Self { address, prefix };
        if prefix > range.bits()
            || range.masked(address) != Some(address)
            || format!("{address}/{prefix}") != value
        {
            return Err(ConnectionError::Destination);
        }
        Ok(range)
    }
    fn bits(&self) -> u8 {
        if self.address.is_ipv4() { 32 } else { 128 }
    }
    fn masked(&self, other: IpAddr) -> Option<IpAddr> {
        match (self.address, other) {
            (IpAddr::V4(_), IpAddr::V4(a)) if self.prefix <= 32 => {
                let mask = u32::MAX
                    .checked_shl(u32::from(32 - self.prefix))
                    .unwrap_or(0);
                Some(IpAddr::V4((u32::from(a) & mask).into()))
            }
            (IpAddr::V6(_), IpAddr::V6(a)) if self.prefix <= 128 => {
                let mask = u128::MAX
                    .checked_shl(u32::from(128 - self.prefix))
                    .unwrap_or(0);
                Some(IpAddr::V6((u128::from(a) & mask).into()))
            }
            _ => None,
        }
    }
    fn contains(&self, other: IpAddr) -> bool {
        self.masked(other) == Some(self.address)
    }
    fn contains_range(&self, other: &Self) -> bool {
        self.prefix <= other.prefix && self.contains(other.address)
    }
}

/// Explicit address allowlist plus closed exceptions for non-public networks.
/// The signed routing configuration must own both lists and the IP profile.
pub struct DestinationPolicy {
    pub allowed_ranges: Vec<NetworkRange>,
    pub private_network_ranges: Vec<NetworkRange>,
    pub allow_ip_endpoint: bool,
}

/// DNS answers are admitted together, off the dispatch path. No address can be
/// silently discarded from a mixed allowed/prohibited answer.
pub struct Resolution {
    pub addresses: Vec<IpAddr>,
    pub resolved_at_ms: u64,
    pub valid_until_ms: u64,
    pub generation: u64,
}

pub struct PreparedEndpoint {
    pub(super) endpoint_id: String,
    pub(super) endpoint_generation: u64,
    pub(super) resolution_generation: u64,
    pub(super) descriptor_digest: pc_runtime_types::Digest,
    pub(super) resolution_digest: pc_runtime_types::Digest,
    authority_configuration: ciborium::value::Value,
    pub(super) url: Url,
    pub(super) reference_identity: String,
    pub(super) addresses: Vec<SocketAddr>,
    pub(super) resolved_at_ms: u64,
    pub(super) valid_until_ms: u64,
}

impl PreparedEndpoint {
    /// The configuration authorized across targets. Resolution generation and
    /// lease timestamps are target-local freshness state, so they are covered
    /// by `resolution_digest` and `valid_until_ms` rather than this identity.
    pub(super) fn authority_configuration_value(&self) -> ciborium::value::Value {
        self.authority_configuration.clone()
    }
}

impl EndpointDescriptor {
    pub fn prepare(
        &self,
        policy: &DestinationPolicy,
        resolution: Resolution,
    ) -> Result<PreparedEndpoint, ConnectionError> {
        let url = Url::parse(&self.normalized_uri).map_err(|_| ConnectionError::Endpoint)?;
        let host = url.host_str().ok_or(ConnectionError::Endpoint)?;
        let ip_host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .ok();
        let reference = ip_host.map_or_else(|| host.to_owned(), |ip| ip.to_string());
        if url.scheme() != "https"
            || url.as_str() != self.normalized_uri
            || !url.username().is_empty()
            || url.password().is_some()
            || self
                .normalized_uri
                .split('/')
                .nth(2)
                .is_some_and(|s| s.contains('@'))
            || url.fragment().is_some()
            || url.port_or_known_default() != Some(self.port)
            || self.port == 0
            || self.path != url.path()
            || reference != self.reference_identity
            || self.endpoint_generation == 0
            || self.normalized_uri.len() > 4096
            || [
                &self.endpoint_id,
                &self.dns_policy_ref,
                &self.tls_policy_ref,
                &self.credential_ref,
                &self.egress_policy_ref,
            ]
            .iter()
            .any(|v| v.is_empty() || v.len() > 160 || !v.bytes().all(|c| c.is_ascii_graphic()))
            || (ip_host.is_some() && !policy.allow_ip_endpoint)
            || (ip_host.is_none() && !canonical_fqdn(host))
        {
            return Err(ConnectionError::Endpoint);
        }

        let now = now_ms()?;
        if resolution.generation == 0
            || resolution.resolved_at_ms > now
            || resolution.valid_until_ms <= now
            || resolution.valid_until_ms <= resolution.resolved_at_ms
        {
            return Err(ConnectionError::Expired);
        }
        let restricted = restricted_ranges();
        if policy.allowed_ranges.is_empty()
            || policy.allowed_ranges.len() > 64
            || policy.private_network_ranges.len() > 64
            || policy
                .private_network_ranges
                .iter()
                .any(|r| !restricted.iter().any(|closed| closed.contains_range(r)))
            || resolution.addresses.is_empty()
            || resolution.addresses.len() > 64
        {
            return Err(ConnectionError::Destination);
        }
        let mut unique = BTreeSet::new();
        for address in &resolution.addresses {
            // Mapped addresses must use their actual IPv4 family, never bypass
            // IPv4 egress classification through an IPv6 representation.
            let mapped = matches!(address, IpAddr::V6(a) if a.to_ipv4_mapped().is_some());
            let public = match address {
                IpAddr::V4(_) => !restricted.iter().any(|r| r.contains(*address)),
                IpAddr::V6(a) => {
                    (a.segments()[0] & 0xe000 == 0x2000)
                        && !restricted.iter().any(|r| r.contains(*address))
                }
            };
            if mapped
                || !unique.insert(*address)
                || ip_host.is_some_and(|a| a != *address)
                || !policy.allowed_ranges.iter().any(|r| r.contains(*address))
                || (!public
                    && !policy
                        .private_network_ranges
                        .iter()
                        .any(|r| r.contains(*address)))
            {
                return Err(ConnectionError::Destination);
            }
        }
        use ciborium::value::Value;
        let configuration = Value::Array(vec![
            Value::Text(self.endpoint_id.clone()),
            Value::Integer(self.endpoint_generation.into()),
            Value::Text(self.normalized_uri.clone()),
            Value::Text(self.reference_identity.clone()),
            Value::Integer(self.port.into()),
            Value::Text(self.path.clone()),
            Value::Text(self.dns_policy_ref.clone()),
            Value::Text(self.tls_policy_ref.clone()),
            Value::Text(self.credential_ref.clone()),
            Value::Text(self.egress_policy_ref.clone()),
            Value::Integer(resolution.generation.into()),
            Value::Integer(resolution.resolved_at_ms.into()),
            Value::Integer(resolution.valid_until_ms.into()),
            Value::Array(
                resolution
                    .addresses
                    .iter()
                    .map(|a| Value::Text(a.to_string()))
                    .collect(),
            ),
            Value::Array(
                policy
                    .allowed_ranges
                    .iter()
                    .map(|r| Value::Text(format!("{}/{}", r.address, r.prefix)))
                    .collect(),
            ),
            Value::Array(
                policy
                    .private_network_ranges
                    .iter()
                    .map(|r| Value::Text(format!("{}/{}", r.address, r.prefix)))
                    .collect(),
            ),
            Value::Bool(policy.allow_ip_endpoint),
        ]);
        let values = configuration.as_array().expect("constructed array");
        let descriptor_digest = pc_runtime_types::Digest::of(pc_policy_core::pc_cbor_1(
            &Value::Array(values[..10].to_vec()),
        ));
        let resolution_digest = pc_runtime_types::Digest::of(pc_policy_core::pc_cbor_1(
            &Value::Array(values[10..14].to_vec()),
        ));
        let authority_configuration =
            Value::Array(values[..10].iter().chain(&values[13..]).cloned().collect());
        Ok(PreparedEndpoint {
            endpoint_id: self.endpoint_id.clone(),
            endpoint_generation: self.endpoint_generation,
            resolution_generation: resolution.generation,
            descriptor_digest,
            resolution_digest,
            authority_configuration,
            url,
            reference_identity: reference,
            addresses: resolution
                .addresses
                .into_iter()
                .map(|ip| SocketAddr::new(ip, self.port))
                .collect(),
            resolved_at_ms: resolution.resolved_at_ms,
            valid_until_ms: resolution.valid_until_ms,
        })
    }
}

fn canonical_fqdn(host: &str) -> bool {
    host.is_ascii()
        && host.len() <= 253
        && host.contains('.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn restricted_ranges() -> Vec<NetworkRange> {
    // Conservatively reject special-purpose networks, including transition,
    // documentation and benchmark space, unless a closed local profile owns
    // that exact subnet. Unknown IPv6 space is not public by default.
    [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "100::/64",
        "2001::/23",
        "2001:db8::/32",
        "2002::/16",
        "3fff::/20",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    ]
    .map(|s| NetworkRange::parse(s).expect("static canonical network"))
    .into()
}
