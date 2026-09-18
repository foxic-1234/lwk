//! Silent payments sweep transaction construction and signing.

use std::collections::HashMap;
use std::str::FromStr;

use lwk_common::set_genesis_hash;
use lwk_wollet::elements::confidential::{
    Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor,
};
use lwk_wollet::elements::encode::serialize;
use lwk_wollet::elements::hex::{FromHex, ToHex};
use lwk_wollet::elements::pset::{Input, Output, PartiallySignedTransaction};
use lwk_wollet::elements::secp256k1_zkp::{
    Generator, Keypair, Message, PedersenCommitment, RangeProof, SecretKey, SurjectionProof, Tag,
    XOnlyPublicKey,
};
use lwk_wollet::elements::sighash::SighashCache;
use lwk_wollet::elements::{
    Address, AssetId, BlindAssetProofs, BlindValueProofs, OutPoint, Script, TxOut, TxOutSecrets,
    TxOutWitness, Txid,
};
use lwk_wollet::elements_miniscript::psbt::{PsbtExt, PsbtSighashMsg};
use lwk_wollet::hashes::Hash;
use lwk_wollet::secp256k1::rand::thread_rng;
use lwk_wollet::{Network, EC};
use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::Error;

/// Input JSON representation of a silent payment UTXO to sweep.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SweepUtxoJson {
    /// Transaction ID (hex)
    pub txid: String,
    /// Output index (vout)
    pub vout: u32,
    /// Amount in satoshis
    #[serde(deserialize_with = "deserialize_u64_from_str_or_num")]
    pub amount_sats: u64,
    /// Asset ID (hex)
    pub asset_id: String,
    /// Asset blinding factor (hex, 32 bytes)
    pub asset_blinding_factor: String,
    /// Value blinding factor (hex, 32 bytes)
    pub value_blinding_factor: String,
    /// Spending private key (hex, 32 bytes)
    pub spending_private_key: String,
}

fn deserialize_u64_from_str_or_num<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StrOrNum {
        Num(u64),
        Str(String),
    }
    match StrOrNum::deserialize(deserializer)? {
        StrOrNum::Num(n) => Ok(n),
        StrOrNum::Str(s) => s.parse::<u64>().map_err(serde::de::Error::custom),
    }
}

/// Estimate virtual size (vSize) for a confidential Taproot sweep transaction.
#[wasm_bindgen(js_name = estimateSweepVsize)]
pub fn estimate_sweep_vsize(num_inputs: u32) -> u32 {
    1225 + 58 * num_inputs
}

/// Construct, blind, sign and extract a consensus-encoded raw transaction (hex)
/// that sweeps one or more Silent Payment stealth UTXOs into a primary wallet confidential address.
#[wasm_bindgen(js_name = createSweepTransaction)]
pub fn create_sweep_transaction(
    utxos_json: &str,
    destination_address: &str,
    fee_sats: u64,
    network: &str,
) -> Result<String, Error> {
    let net = match network.to_ascii_lowercase().as_str() {
        "mainnet" | "liquid" => Network::Liquid,
        "testnet" | "testnetliquid" => Network::TestnetLiquid,
        _ => Network::default_regtest(),
    };

    let dest_addr = Address::from_str(destination_address)
        .map_err(|e| Error::Generic(format!("Invalid destination address: {e}")))?;
    let dest_script = dest_addr.script_pubkey();
    let dest_blinding_pk = dest_addr.blinding_pubkey;

    let policy_asset = net.policy_asset();

    let utxos: Vec<SweepUtxoJson> = serde_json::from_str(utxos_json)
        .map_err(|e| Error::Generic(format!("Invalid utxos JSON: {e}")))?;

    if utxos.is_empty() {
        return Err(Error::Generic("No UTXOs provided to sweep".to_string()));
    }

    let mut pset = PartiallySignedTransaction::new_v2();
    set_genesis_hash(&mut pset, &net);

    let mut total_sats: u64 = 0;
    let mut inp_txout_sec: HashMap<usize, TxOutSecrets> = HashMap::with_capacity(utxos.len());
    let mut keypairs = Vec::with_capacity(utxos.len());
    let mut rng = thread_rng();

    for (idx, utxo) in utxos.iter().enumerate() {
        let txid = Txid::from_str(&utxo.txid)
            .map_err(|e| Error::Generic(format!("Invalid txid: {e}")))?;
        let outpoint = OutPoint::new(txid, utxo.vout);

        let asset_id = AssetId::from_str(&utxo.asset_id)
            .map_err(|e| Error::Generic(format!("Invalid asset_id: {e}")))?;
        let abf = AssetBlindingFactor::from_str(&utxo.asset_blinding_factor)
            .map_err(|e| Error::Generic(format!("Invalid asset_blinding_factor: {e}")))?;
        let vbf = ValueBlindingFactor::from_str(&utxo.value_blinding_factor)
            .map_err(|e| Error::Generic(format!("Invalid value_blinding_factor: {e}")))?;

        let privkey_bytes = Vec::<u8>::from_hex(&utxo.spending_private_key)
            .map_err(|e| Error::Generic(format!("Invalid spending_private_key hex: {e}")))?;
        let privkey = SecretKey::from_slice(&privkey_bytes)
            .map_err(|e| Error::Generic(format!("Invalid spending_private_key: {e}")))?;
        let keypair = Keypair::from_secret_key(&EC, &privkey);
        let (xonly_pk, _parity) = XOnlyPublicKey::from_keypair(&keypair);

        let mut spk_bytes = vec![0x51, 0x20];
        spk_bytes.extend_from_slice(&xonly_pk.serialize());
        let spk = Script::from(spk_bytes);

        let asset_tag = Tag::from(asset_id.into_inner().to_byte_array());
        let asset_gen = Generator::new_blinded(&EC, asset_tag, abf.into_inner());
        let value_comm = PedersenCommitment::new(&EC, utxo.amount_sats, vbf.into_inner(), asset_gen);

        let input_txout = TxOut {
            asset: Asset::Confidential(asset_gen),
            value: Value::Confidential(value_comm),
            nonce: Nonce::Null,
            script_pubkey: spk,
            witness: TxOutWitness::default(),
        };

        let mut pset_input = Input::from_prevout(outpoint);
        pset_input.asset = Some(asset_id);
        pset_input.amount = Some(utxo.amount_sats);
        pset_input.blind_asset_proof = Some(Box::new(
            SurjectionProof::blind_asset_proof(&mut rng, &EC, asset_id, abf)
                .map_err(|e| Error::Generic(format!("blind_asset_proof error: {e}")))?,
        ));
        pset_input.blind_value_proof = Some(Box::new(
            RangeProof::blind_value_proof(&mut rng, &EC, utxo.amount_sats, value_comm, asset_gen, vbf)
                .map_err(|e| Error::Generic(format!("blind_value_proof error: {e}")))?,
        ));
        pset_input.witness_utxo = Some(input_txout);

        pset.add_input(pset_input);
        inp_txout_sec.insert(idx, TxOutSecrets::new(asset_id, abf, utxo.amount_sats, vbf));
        keypairs.push(keypair);
        total_sats += utxo.amount_sats;
    }

    if total_sats <= fee_sats {
        return Err(Error::Generic(format!(
            "Total input amount ({total_sats} sats) is less than or equal to fee ({fee_sats} sats)"
        )));
    }
    let send_sats = total_sats - fee_sats;

    let dest_output = Output {
        script_pubkey: dest_script,
        amount: Some(send_sats),
        asset: Some(*policy_asset),
        blinding_key: dest_blinding_pk.map(lwk_wollet::bitcoin::PublicKey::new),
        blinder_index: if dest_blinding_pk.is_some() { Some(0) } else { None },
        ..Default::default()
    };
    pset.add_output(dest_output);

    let fee_output = Output {
        script_pubkey: Script::default(),
        amount: Some(fee_sats),
        asset: Some(*policy_asset),
        ..Default::default()
    };
    pset.add_output(fee_output);

    pset.blind_last(&mut rng, &EC, &inp_txout_sec)
        .map_err(|e| Error::Generic(format!("blind_last error: {e}")))?;

    let tx = pset
        .extract_tx()
        .map_err(|e| Error::Generic(format!("extract_tx error before sign: {e}")))?;
    let mut sighash_cache = SighashCache::new(&tx);
    let genesis_hash = lwk_common::get_genesis_hash(&pset);

    for (i, keypair) in keypairs.iter().enumerate() {
        let msg = pset
            .sighash_msg(i, &mut sighash_cache, None, genesis_hash)
            .map_err(|e| Error::Generic(format!("sighash_msg error: {e}")))?;
        if let PsbtSighashMsg::TapSighash(hash) = msg {
            let secp_msg = Message::from_digest(hash.to_byte_array());
            let sig = EC.sign_schnorr(&secp_msg, keypair);
            pset.inputs_mut()[i].final_script_witness = Some(vec![sig.as_ref().to_vec()]);
        } else {
            return Err(Error::Generic("Expected Taproot sighash".to_string()));
        }
    }

    let final_tx = pset
        .extract_tx()
        .map_err(|e| Error::Generic(format!("extract_tx error after sign: {e}")))?;
    let tx_bytes = serialize(&final_tx);
    Ok(tx_bytes.to_hex())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_sweep_transaction() {
        let dest_address = "tlq1qq2xvpcvfup5j8zscjq05u2wxxjcyewk7979f3mmz5l7uw5pqmx6xf5xy50hsn6vhkm5euwt72x878eq6zxx2z58hd7zrsg9qn";
        let utxo_json = r#"[
            {
                "txid": "0000000000000000000000000000000000000000000000000000000000000001",
                "vout": 0,
                "amountSats": 100000,
                "assetId": "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49",
                "assetBlindingFactor": "0000000000000000000000000000000000000000000000000000000000000002",
                "valueBlindingFactor": "0000000000000000000000000000000000000000000000000000000000000003",
                "spendingPrivateKey": "0000000000000000000000000000000000000000000000000000000000000004"
            }
        ]"#;

        let fee_sats = 500;
        let tx_hex = create_sweep_transaction(utxo_json, dest_address, fee_sats, "testnet").unwrap();
        assert!(!tx_hex.is_empty());
        // Verify that tx deserializes as a valid elements Transaction
        let tx_bytes = Vec::<u8>::from_hex(&tx_hex).unwrap();
        let tx: lwk_wollet::elements::Transaction = lwk_wollet::elements::encode::deserialize(&tx_bytes).unwrap();
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 2);
        // First output is blinded (has rangeproof + surjection proof)
        assert!(tx.output[0].witness.rangeproof.is_some());
        assert!(tx.output[0].witness.surjection_proof.is_some());
        // Second output is explicit fee
        assert!(tx.output[1].is_fee());
        assert_eq!(tx.output[1].minimum_value(), fee_sats);
        // Input has Taproot key-path 64-byte signature
        assert_eq!(tx.input[0].witness.script_witness.len(), 1);
        assert_eq!(tx.input[0].witness.script_witness[0].len(), 64);
    }
}
