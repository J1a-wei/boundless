use alloy::{
    primitives::{Address, Bytes, FixedBytes, U256},
    providers::{Provider, WalletProvider},
    rpc::types::TransactionReceipt,
};
use anyhow::{Context, Result};
use boundless_market::{
    contracts::{
        boundless_market::{IBoundlessMarket},
        ProofRequest,
    },
    Deployment,
};
use serde::{Deserialize, Serialize};
use std::{str::FromStr, sync::Arc};

use crate::db::DbObj;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderRequest {
    pub request: ProofRequest,
    pub client_sig: Bytes,
    pub fulfillment_type: FulfillmentType,
    pub boundless_market_address: Address,
    pub chain_id: u64,
    pub image_id: Option<String>,
    pub input_id: Option<String>,
    pub total_cycles: Option<u64>,
    pub target_timestamp: Option<u64>,
    pub expire_timestamp: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FulfillmentType {
    LockAndFulfill,
    FulfillAfterLockExpire,
}

impl OrderRequest {
    pub fn new(
        request: ProofRequest,
        client_sig: Bytes,
        fulfillment_type: FulfillmentType,
        boundless_market_address: Address,
        chain_id: u64,
    ) -> Self {
        Self {
            request,
            client_sig,
            fulfillment_type,
            boundless_market_address,
            chain_id,
            image_id: None,
            input_id: None,
            total_cycles: None,
            target_timestamp: None,
            expire_timestamp: None,
        }
    }

    pub fn id(&self) -> String {
        let signing_hash = self
            .request
            .signing_hash(self.boundless_market_address, self.chain_id)
            .unwrap();
        format_order_id(&self.request.id, &signing_hash, &self.fulfillment_type)
    }
}

fn format_order_id(
    request_id: &U256,
    signing_hash: &FixedBytes<32>,
    fulfillment_type: &FulfillmentType,
) -> String {
    format!("0x{request_id:x}-{signing_hash}-{fulfillment_type:?}")
}

pub struct RecalculateService<P>
where
    P: Provider + 'static + Clone + WalletProvider,
{
    provider: Arc<P>,
    db: DbObj,
    deployment: Deployment,
}

impl<P> RecalculateService<P>
where
    P: Provider + 'static + Clone + WalletProvider,
{
    pub fn new(provider: Arc<P>, db: DbObj, deployment: Deployment) -> Self {
        Self {
            provider,
            db,
            deployment,
        }
    }

    pub async fn recalculate_locked_order(&self, tx_hash: &str) -> Result<()> {
        tracing::info!("Recalculating locked order from transaction hash: {}", tx_hash);

        // Parse transaction hash
        let tx_hash = if tx_hash.starts_with("0x") {
            tx_hash.to_string()
        } else {
            format!("0x{}", tx_hash)
        };

        // Get transaction receipt
        let receipt = self
            .provider
            .get_transaction_receipt(FixedBytes::from_str(&tx_hash)?)
            .await
            .context("Failed to get transaction receipt")?;

        let receipt = receipt.ok_or_else(|| anyhow::anyhow!("Transaction not found"))?;

        // Extract RequestLocked event from transaction logs
        let locked_event = self.extract_locked_event(&receipt)?;

        // Create order request from the locked event
        let order_request = OrderRequest::new(
            locked_event.request.clone(),
            locked_event.clientSignature.clone(),
            FulfillmentType::LockAndFulfill,
            self.deployment.boundless_market_address,
            self.provider.get_chain_id().await?,
        );

        // Check if order is already in database
        let order_id = order_request.id();
        let is_locked = self
            .db
            .is_request_locked(U256::from(locked_event.requestId))
            .await
            .context("Failed to check if request is locked")?;

        if is_locked {
            tracing::info!("Order {} is already locked in database", order_id);
            return Ok(());
        }

        // Store the locked request in database
        self.db
            .set_request_locked(
                U256::from(locked_event.requestId),
                &locked_event.prover.to_string(),
                receipt.block_number.context("Missing block number")?,
            )
            .await
            .context("Failed to store locked request")?;

        tracing::info!(
            "Successfully recalculated and stored locked order: {} (request ID: 0x{:x})",
            order_id,
            locked_event.requestId
        );

        Ok(())
    }

    fn extract_locked_event(&self, receipt: &TransactionReceipt) -> Result<IBoundlessMarket::RequestLocked> {
        let logs = receipt
            .inner
            .logs()
            .iter()
            .filter_map(|log| {
                if log.topic0().map(|topic| IBoundlessMarket::RequestLocked::SIGNATURE_HASH == *topic).unwrap_or(false) {
                    Some(
                        log.log_decode::<IBoundlessMarket::RequestLocked>()
                            .with_context(|| format!("failed to decode RequestLocked event")),
                    )
                } else {
                    None
                }
            })
            .collect::<Result<Vec<_>>>()?;

        match &logs[..] {
            [event] => Ok(event.inner.data.clone()),
            [] => Err(anyhow::anyhow!(
                "transaction 0x{:x} did not emit RequestLocked event",
                receipt.transaction_hash
            )),
            _ => Err(anyhow::anyhow!(
                "transaction emitted more than one RequestLocked event: {:#?}",
                logs
            )),
        }
    }
} 