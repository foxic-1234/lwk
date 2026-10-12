//! External UTXO

use crate::{Error, OutPoint, Script, Transaction, TxOutSecrets};
use wasm_bindgen::prelude::*;

/// An external UTXO, owned by another wallet.
#[wasm_bindgen]
pub struct ExternalUtxo {
    inner: lwk_wollet::ExternalUtxo,
}

impl From<lwk_wollet::ExternalUtxo> for ExternalUtxo {
    fn from(inner: lwk_wollet::ExternalUtxo) -> Self {
        Self { inner }
    }
}

impl From<ExternalUtxo> for lwk_wollet::ExternalUtxo {
    fn from(value: ExternalUtxo) -> Self {
        value.inner
    }
}

impl From<&ExternalUtxo> for lwk_wollet::ExternalUtxo {
    fn from(value: &ExternalUtxo) -> Self {
        value.inner.clone()
    }
}

#[wasm_bindgen]
impl ExternalUtxo {
    /// Construct an ExternalUtxo
    #[wasm_bindgen(constructor)]
    pub fn new(
        vout: u32,
        tx: &Transaction,
        unblinded: &TxOutSecrets,
        max_weight_to_satisfy: u32,
        is_segwit: bool,
    ) -> Result<ExternalUtxo, Error> {
        let tx: lwk_wollet::elements::Transaction = tx.as_ref().clone();
        let txout = tx
            .output
            .get(vout as usize)
            .ok_or_else(|| Error::Generic("Transaction does not have enough outputs".to_string()))?
            .clone();
        let outpoint = lwk_wollet::elements::OutPoint::new(tx.txid(), vout);
        let tx = if is_segwit { None } else { Some(tx) };
        let utxo = lwk_wollet::ExternalUtxo {
            outpoint,
            txout,
            tx,
            unblinded: unblinded.into(),
            max_weight_to_satisfy: max_weight_to_satisfy as usize,
        };
        Ok(utxo.into())
    }

    /// Construct an ExternalUtxo directly from outpoint, scriptPubkey, and TxOutSecrets.
    #[wasm_bindgen(js_name = newUnblinded)]
    pub fn new_unblinded(
        outpoint: &OutPoint,
        script_pubkey: &Script,
        unblinded: &TxOutSecrets,
        max_weight_to_satisfy: u32,
    ) -> Result<ExternalUtxo, Error> {
        let secrets: lwk_wollet::elements::TxOutSecrets = unblinded.into();
        let is_explicit = secrets.asset_bf == lwk_wollet::elements::confidential::AssetBlindingFactor::zero()
            && secrets.value_bf == lwk_wollet::elements::confidential::ValueBlindingFactor::zero();
        let (asset, value) = if is_explicit {
            (
                lwk_wollet::elements::confidential::Asset::Explicit(secrets.asset),
                lwk_wollet::elements::confidential::Value::Explicit(secrets.value),
            )
        } else {
            let asset_tag = lwk_wollet::elements::secp256k1_zkp::Tag::from(secrets.asset.into_inner().to_byte_array());
            let asset_gen = lwk_wollet::elements::secp256k1_zkp::Generator::new_blinded(
                &lwk_wollet::EC,
                asset_tag,
                secrets.asset_bf.into_inner(),
            );
            let value_comm = lwk_wollet::elements::secp256k1_zkp::PedersenCommitment::new(
                &lwk_wollet::EC,
                secrets.value,
                secrets.value_bf.into_inner(),
                asset_gen,
            );
            (
                lwk_wollet::elements::confidential::Asset::Confidential(asset_gen),
                lwk_wollet::elements::confidential::Value::Confidential(value_comm),
            )
        };
        let txout = lwk_wollet::elements::TxOut {
            asset,
            value,
            nonce: lwk_wollet::elements::confidential::Nonce::Null,
            script_pubkey: script_pubkey.as_ref().clone(),
            witness: lwk_wollet::elements::TxOutWitness::default(),
        };
        let utxo = lwk_wollet::ExternalUtxo {
            outpoint: outpoint.into(),
            txout,
            tx: None,
            unblinded: secrets,
            max_weight_to_satisfy: max_weight_to_satisfy as usize,
        };
        Ok(utxo.into())
    }
}
