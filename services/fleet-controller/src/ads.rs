//! Real SOTW ADS. Only verified TLS peers can advance Fleet's ACK barrier.
use crate::ads_discovery::{Connections, TargetDiscovery};
use crate::{
    FleetController, REQUIRED_XDS_TYPES, TargetIdentity, XdsSnapshot,
    ads_wire::{DiscoveryRequest, DiscoveryResponse, ResourceName},
};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult, TargetState, canonical_bytes};
use prost::Message;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};
use tokio::sync::{mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

#[derive(Clone)]
struct Published {
    version: Digest,
    resources: BTreeMap<String, Vec<prost_types::Any>>,
    nonces: BTreeMap<String, String>,
    resource_names: BTreeMap<String, Vec<String>>,
}
#[derive(Clone)]
pub struct AdsService {
    fleet: Arc<FleetController>,
    published: Arc<Mutex<BTreeMap<String, Published>>>,
    changed: watch::Sender<u64>,
    discovery: Option<Arc<dyn TargetDiscovery>>,
    connections: Connections,
    pub(crate) target_disposition:
        Option<crate::target_disposition_transport::TargetDispositionService>,
}
impl AdsService {
    pub fn new(fleet: Arc<FleetController>) -> Self {
        let (changed, _) = watch::channel(0);
        Self {
            fleet,
            published: Arc::new(Mutex::new(BTreeMap::new())),
            changed,
            discovery: None,
            connections: Connections::default(),
            target_disposition: None,
        }
    }
    pub fn with_discovery(mut self, discovery: Arc<dyn TargetDiscovery>) -> Self {
        self.discovery = Some(discovery);
        self
    }

    pub fn with_target_disposition(
        mut self,
        store: Arc<crate::target_disposition::TargetDispositionStore>,
    ) -> Self {
        self.target_disposition = Some(
            crate::target_disposition_transport::TargetDispositionService::new(
                Arc::clone(&self.fleet),
                store,
            ),
        );
        self
    }

    /// Caller retains the current database authority fences through this effect.
    pub fn with_current_connection<T>(
        &self,
        target: &str,
        id: &str,
        action: impl FnOnce() -> T,
    ) -> Result<T, Status> {
        self.connections.with_current(target, id, action)
    }
    pub(crate) fn belongs_to(&self, fleet: &Arc<FleetController>) -> bool {
        Arc::ptr_eq(&self.fleet, fleet)
    }
    pub fn resource_version(
        resources: &BTreeMap<String, Vec<prost_types::Any>>,
    ) -> RuntimeResult<Digest> {
        let semantic: BTreeMap<_, Vec<_>> = resources
            .iter()
            .map(|(kind, items)| {
                (
                    kind,
                    items.iter().map(|a| (&a.type_url, &a.value)).collect(),
                )
            })
            .collect();
        Ok(Digest::of(canonical_bytes(&semantic)?))
    }
    pub fn publish(
        &self,
        target_id: &str,
        resources: BTreeMap<String, Vec<prost_types::Any>>,
    ) -> RuntimeResult<Digest> {
        let version = Self::resource_version(&resources)?;
        self.publish_version(target_id, resources, version.clone())?;
        Ok(version)
    }

    /// Publish resources under the release owner's already persisted opaque
    /// xDS version. The version is a deployment identity, while every resource
    /// is still decoded and constrained to the authenticated target namespace.
    pub fn publish_version(
        &self,
        target_id: &str,
        resources: BTreeMap<String, Vec<prost_types::Any>>,
        version: Digest,
    ) -> RuntimeResult<()> {
        if target_id.is_empty() {
            return Err(RuntimeError::InvalidInput);
        }
        let mut names = BTreeMap::new();
        for (kind, items) in &resources {
            let mut group = Vec::new();
            for resource in items {
                if &resource.type_url != kind
                    || resource.value.is_empty()
                    || resource.value.len() > 4 * 1024 * 1024
                {
                    return Err(RuntimeError::InvalidInput);
                }
                let name = ResourceName::decode(resource.value.as_slice())
                    .map_err(|_| RuntimeError::InvalidInput)?
                    .name;
                if group.contains(&name) {
                    return Err(RuntimeError::InvalidInput);
                }
                group.push(name);
            }
            names.insert(kind.clone(), group);
        }
        let mut published = self
            .published
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let nonces = self.fleet.publish_snapshot(XdsSnapshot {
            target_id: target_id.to_owned(),
            version_digest: version.clone(),
            resources_by_type: names.clone(),
        })?;
        published.insert(
            target_id.to_owned(),
            Published {
                version: version.clone(),
                resources,
                nonces,
                resource_names: names,
            },
        );
        self.changed
            .send_modify(|sequence| *sequence = sequence.wrapping_add(1));
        Ok(())
    }
    fn snapshot(&self, identity: &TargetIdentity) -> Result<Option<Published>, Status> {
        // Match publication's lock order. A re-registered target may have lost
        // its Fleet snapshot while ADS still retains the previous resource bytes.
        let published = self
            .published
            .lock()
            .map_err(|_| Status::unavailable("ADS owner unavailable"))?;
        let targets = self
            .fleet
            .targets
            .lock()
            .map_err(|_| Status::unavailable("Fleet owner unavailable"))?;
        let target = targets
            .get(&identity.target_id)
            .filter(|target| target.identity == *identity)
            .ok_or_else(|| status(RuntimeError::TargetIdentity))?;
        Ok(published
            .get(&identity.target_id)
            .filter(|publication| {
                matches!(
                    target.state,
                    TargetState::XdsPending
                        | TargetState::XdsAckedNotActive
                        | TargetState::Activating
                        | TargetState::ActiveMatched
                ) && target
                    .desired
                    .as_ref()
                    .is_some_and(|desired| desired.xds_snapshot_digest == publication.version)
                    && target.snapshot.as_ref().is_some_and(|snapshot| {
                        snapshot.version_digest == publication.version
                            && snapshot.resources_by_type == publication.resource_names
                    })
                    && target.nonce_by_type == publication.nonces
                    && !target.quarantined_versions.contains(&publication.version)
            })
            .cloned())
    }
    pub(crate) async fn stream(
        &self,
        request: Request<Streaming<DiscoveryRequest>>,
    ) -> Result<Response<ReceiverStream<Result<DiscoveryResponse, Status>>>, Status> {
        let (identity, certificate_until_ms) =
            crate::runtime_tls::authenticated_target(request.extensions(), &self.fleet)?;
        let mut incoming = request.into_inner();
        let owner = self.clone();
        let mut changed = self.changed.subscribe();
        let (sender, receiver) = mpsc::channel(8);
        tokio::spawn(async move {
            let mut subscriptions = BTreeMap::<String, Vec<String>>::new();
            let mut sent = BTreeMap::<String, (Digest, String, bool)>::new();
            let mut first = true;
            let mut connection = None;
            let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
            heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                let result:Result<(),Status>=async {
                    tokio::select! {
                        message=incoming.message()=>{
                            let message=message?.ok_or_else(||Status::cancelled("ADS stream closed"))?;
                            if (first && message.node.is_none()) || message.node.as_ref().is_some_and(|n|n.id!=identity.target_id)
                                || !message.resource_locators.is_empty() || !REQUIRED_XDS_TYPES.contains(&message.type_url.as_str())
                            {return Err(Status::permission_denied("ADS target or resource rejected"));}
                            owner.fleet.check_current_peer(&identity).map_err(status)?;
                            if !message.response_nonce.is_empty(){
                                let (version,nonce,acked)=sent.get_mut(&message.type_url).ok_or_else(||Status::failed_precondition("unsolicited ADS acknowledgement"))?;
                                if *nonce!=message.response_nonce{return Err(Status::failed_precondition("stale ADS nonce"));}
                                if message.error_detail.is_some(){
                                    // A NACK carries the previously applied version, not the rejected version.
                                    owner.fleet.nack(&identity,version,nonce).map_err(status)?;
                                    return Err(Status::failed_precondition("xDS version quarantined"));
                                }
                                if message.version_info!=version.as_str(){return Err(Status::failed_precondition("ADS version mismatch"));}
                                if !*acked {owner.fleet.acknowledge(&identity,&message.type_url,version,nonce).map_err(status)?;*acked=true;}
                            }
                            let names:BTreeSet<_>=message.resource_names.iter().collect();
                            if names.len()!=message.resource_names.len(){return Err(Status::invalid_argument("duplicate resource subscription"));}
                            if first {
                                connection = Some(owner.connections.open(&identity.target_id)?);
                                first = false;
                            }
                            subscriptions.insert(message.type_url,message.resource_names);
                        }
                        update=changed.changed()=>{update.map_err(|_|Status::unavailable("ADS owner closed"))?;}
                        _=heartbeat.tick()=>{}
                        _=sender.closed()=>{return Err(Status::cancelled("ADS receiver closed"));}
                    }
                    if let Some(connection) = &connection {
                        let now_ms = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)
                            .map_err(|_| Status::unavailable("ADS clock unavailable"))?.as_millis())
                            .map_err(|_| Status::unavailable("ADS clock unavailable"))?;
                        let remaining = certificate_until_ms.checked_sub(now_ms).filter(|v| *v > 0)
                            .ok_or_else(|| Status::unauthenticated("ADS certificate expired"))?;
                        if let Some(discovery) = &owner.discovery {
                            discovery.observe(&identity, &connection.id, certificate_until_ms).await?;
                        }
                        connection.renew(Duration::from_millis(remaining))?;
                    }
                    if let Some(snapshot)=owner.snapshot(&identity)? {
                        for (kind,wanted) in &subscriptions {
                            if sent.get(kind).is_some_and(|(v,_,_)|*v==snapshot.version){continue;}
                            let resources=snapshot.resources.get(kind).ok_or_else(||Status::failed_precondition("incomplete snapshot"))?;
                            let available:BTreeSet<_>=resources.iter().map(|a|ResourceName::decode(a.value.as_slice()).map(|r|r.name)).collect::<Result<_,_>>()
                                .map_err(|_|Status::internal("invalid admitted resource"))?;
                            if !wanted.is_empty() && wanted.iter().cloned().collect::<BTreeSet<_>>()!=available{return Err(Status::permission_denied("resource subscription outside target snapshot"));}
                            let nonce=snapshot.nonces.get(kind).ok_or_else(||Status::internal("missing nonce"))?.clone();
                            sender.send(Ok(DiscoveryResponse{version_info:snapshot.version.as_str().into(),resources:resources.clone(),type_url:kind.clone(),nonce:nonce.clone()}))
                                .await.map_err(|_|Status::cancelled("ADS receiver closed"))?;
                            sent.insert(kind.clone(),(snapshot.version.clone(),nonce,false));
                        }
                    }
                    Ok(())
                }.await;
                if let Err(error) = result {
                    if let Some(connection) = connection.take() {
                        let id = connection.id.clone();
                        drop(connection);
                        if let Some(discovery) = &owner.discovery {
                            discovery.disconnect(&identity, &id).await;
                        }
                    }
                    let _ = sender.send(Err(error)).await;
                    break;
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(receiver)))
    }
}
fn status(error: RuntimeError) -> Status {
    match error {
        RuntimeError::TargetIdentity => Status::permission_denied(error.pc_code()),
        RuntimeError::RuntimeUnavailable => Status::unavailable(error.pc_code()),
        _ => Status::failed_precondition(error.pc_code()),
    }
}
impl FleetController {
    pub(crate) fn check_current_peer(&self, identity: &TargetIdentity) -> RuntimeResult<()> {
        let targets = self
            .targets
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        if targets
            .get(&identity.target_id)
            .is_none_or(|target| target.identity != *identity)
        {
            return Err(RuntimeError::TargetIdentity);
        }
        Ok(())
    }
}
