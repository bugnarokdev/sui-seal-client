//! Minimal Sui fullnode reads over gRPC (`sui-rpc`).

use std::time::Duration;

use sui_rpc::field::{FieldMask, FieldMaskUtil};
use sui_rpc::proto::sui::rpc::v2::{
    GetObjectRequest, ListDynamicFieldsRequest, Object, owner::OwnerKind,
};
use sui_sdk_types::Address;

use crate::error::{Error, Result};

const RPC_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone)]
pub(crate) struct Rpc {
    client: sui_rpc::Client,
}

impl Rpc {
    pub(crate) fn new(url: &str) -> Result<Self> {
        let client = sui_rpc::Client::new(url).map_err(|e| Error::Rpc(e.to_string()))?;
        Ok(Self { client })
    }

    pub(crate) async fn get_object(&self, id: &Address, mask: &str) -> Result<Object> {
        let mut client = self.client.clone();
        let request = GetObjectRequest::default()
            .with_object_id(id.to_string())
            .with_read_mask(FieldMask::from_str(mask));
        let reply = tokio::time::timeout(RPC_TIMEOUT, client.ledger_client().get_object(request))
            .await
            .map_err(|_| Error::Rpc(format!("GetObject {id} timed out")))?
            .map_err(|s| Error::Rpc(format!("GetObject {id}: {:?} {}", s.code(), s.message())))?
            .into_inner();
        reply
            .object
            .ok_or_else(|| Error::Rpc(format!("GetObject {id}: empty reply")))
    }

    /// BCS of the Move struct contents of an object.
    pub(crate) async fn object_contents(&self, id: &Address) -> Result<Vec<u8>> {
        let object = self.get_object(id, "contents").await?;
        object
            .contents
            .and_then(|b| b.value)
            .map(|b| b.to_vec())
            .ok_or_else(|| Error::Rpc(format!("object {id} has no Move contents")))
    }

    /// Value BCS of the dynamic field of `parent` whose name BCS equals `name_bcs`.
    pub(crate) async fn dynamic_field_value(
        &self,
        parent: &Address,
        name_bcs: &[u8],
    ) -> Result<Vec<u8>> {
        let mut client = self.client.clone();
        let mut token = None;
        for _ in 0..20 {
            let mut request = ListDynamicFieldsRequest::default()
                .with_parent(parent.to_string())
                .with_page_size(50u32)
                .with_read_mask(FieldMask::from_paths(["name", "value"]));
            if let Some(t) = token.take() {
                request = request.with_page_token(t);
            }
            let reply = tokio::time::timeout(
                RPC_TIMEOUT,
                client.state_client().list_dynamic_fields(request),
            )
            .await
            .map_err(|_| Error::Rpc(format!("ListDynamicFields {parent} timed out")))?
            .map_err(|s| {
                Error::Rpc(format!(
                    "ListDynamicFields {parent}: {:?} {}",
                    s.code(),
                    s.message()
                ))
            })?
            .into_inner();
            for field in reply.dynamic_fields {
                let name = field.name.and_then(|b| b.value);
                if name.as_deref() == Some(name_bcs) {
                    return field
                        .value
                        .and_then(|b| b.value)
                        .map(|b| b.to_vec())
                        .ok_or_else(|| Error::Rpc("dynamic field without value".into()));
                }
            }
            match reply.next_page_token {
                Some(t) if !t.is_empty() => token = Some(t),
                _ => break,
            }
        }
        Err(Error::Rpc(format!(
            "dynamic field not found under {parent}"
        )))
    }

    /// Initial shared version of a shared object.
    pub(crate) async fn initial_shared_version(&self, id: &Address) -> Result<u64> {
        let object = self.get_object(id, "owner").await?;
        let owner = object
            .owner
            .ok_or_else(|| Error::Rpc(format!("object {id} has no owner info")))?;
        if owner.kind != Some(OwnerKind::Shared as i32) {
            return Err(Error::InvalidInput(format!("object {id} is not shared")));
        }
        owner
            .version
            .ok_or_else(|| Error::Rpc(format!("object {id}: missing initial shared version")))
    }

    /// Object version (packages: 1 for the original publish).
    pub(crate) async fn object_version(&self, id: &Address) -> Result<u64> {
        let object = self.get_object(id, "version").await?;
        object
            .version
            .ok_or_else(|| Error::Rpc(format!("object {id}: missing version")))
    }
}
