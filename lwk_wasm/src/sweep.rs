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
    Generator, Keypair, PedersenCommitment, PublicKey as SecpPublicKey, RangeProof, SecretKey,
    SurjectionProof, Tag, XOnlyPublicKey,
};
use lwk_wollet::elements::sighash::SighashCache;
use lwk_wollet::elements::{
    Address, AssetId, BlindAssetProofs, BlindValueProofs, OutPoint, Script, TxOut, TxOutSecrets,
    TxOutWitness, Txid,
};
use lwk_wollet::elements_miniscript::psbt::PsbtExt;
use lwk_wollet::hashes::hash160::Hash as Hash160;
use lwk_wollet::hashes::Hash;
use lwk_wollet::secp256k1::rand::thread_rng;
use lwk_wollet::{Network, EC};
use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::Error;

use zeroize::{Zeroize, Zeroizing};

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
    /// Optional spending private key (hex, 32 bytes) - legacy fallback.
    /// In modern calls, private keys should be passed as raw bytes in `spending_keys` Uint8Array.
    #[serde(default)]
    pub spending_private_key: Option<String>,
    /// Script type: "p2tr" (default) or "p2wpkh"
    #[serde(default)]
    pub script_type: Option<String>,
}

enum InputSigner {
    Taproot(Zeroizing<[u8; 32]>),
    SegwitV0(Zeroizing<[u8; 32]>, SecpPublicKey),
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

/// Network explicit dust limit threshold in satoshis for Liquid (Elements).
/// Any change output below this limit must not be created, because Liquid nodes
/// reject dust outputs or render them uneconomical (spending fee exceeds value).
/// If change is below this threshold, it is absorbed into the miner fee.
pub const DUST_LIMIT_SATS: u64 = 600;

/// Base virtual size for a confidential transaction with 1 confidential recipient output + 1 explicit fee output.
/// In Elements/Liquid, 1 confidential P2TR output with RangeProof Bulletproof and SurjectionProof
/// has a discount-adjusted vSize of ~1169 vB, plus base transaction overhead and explicit fee output (~56 vB) = ~1225 vB.
pub const VSIZE_BASE_1_CONFIDENTIAL_OUT: u32 = 1225;

/// Virtual size for an additional confidential change output (with ELIP-200 CT discount).
pub const VSIZE_CONFIDENTIAL_CHANGE_OUT: u32 = 280;

/// Virtual size per P2TR (Taproot key-path) input:
/// Non-witness: 41 bytes (outpoint 36B + scriptSig len 1B + sequence 4B) * 4 = 164 WU.
/// Witness: 1 stack item count (1B) + 1 length byte (1B) + 64B Schnorr sig = 66 WU.
/// Total: 164 + 66 = 230 WU -> ceil(230 / 4) = 58 vB.
pub const VSIZE_P2TR_INPUT: u32 = 58;

/// Virtual size per P2WPKH (Segwit v0) input:
/// Non-witness: 41 bytes * 4 = 164 WU.
/// Witness: 1 stack item count (1B) + 1 len (1B) + 72B DER ECDSA sig + 1 len (1B) + 33B compressed pubkey = 108 WU.
/// Total: 164 + 108 = 272 WU -> ceil(272 / 4) = 68.25 -> 69 vB.
pub const VSIZE_P2WPKH_INPUT: u32 = 69;

/// Calculate virtual size (vSize) for a confidential sweep transaction with specific input types.
pub fn calculate_sweep_vsize(
    num_p2tr_inputs: u32,
    num_p2wpkh_inputs: u32,
    has_change: bool,
) -> u32 {
    let mut base = VSIZE_BASE_1_CONFIDENTIAL_OUT;
    if has_change {
        base += VSIZE_CONFIDENTIAL_CHANGE_OUT;
    }
    base + (num_p2tr_inputs * VSIZE_P2TR_INPUT) + (num_p2wpkh_inputs * VSIZE_P2WPKH_INPUT)
}

/// Estimate virtual size (vSize) for a confidential sweep transaction.
/// Supports both legacy JS call `estimateSweepVsize(num_inputs, has_change)` and granular
/// `estimateSweepVsize(num_inputs, has_change, num_p2wpkh_inputs)`.
#[wasm_bindgen(js_name = estimateSweepVsize)]
pub fn estimate_sweep_vsize(
    num_inputs: u32,
    has_change: Option<bool>,
    num_p2wpkh_inputs: Option<u32>,
) -> u32 {
    let p2wpkh = num_p2wpkh_inputs.unwrap_or(0).min(num_inputs);
    let p2tr = num_inputs.saturating_sub(p2wpkh);
    calculate_sweep_vsize(p2tr, p2wpkh, has_change.unwrap_or(false))
}

/// Construct, blind, sign and extract a consensus-encoded raw transaction (hex)
/// that sweeps one or more Silent Payment stealth UTXOs into a primary wallet confidential address,
/// or sends a specific amount to a destination address with change returning to a change address.
///
/// # Security (M3)
/// `spending_keys`: Raw 32-byte private keys for each UTXO concatenated into a single byte buffer
/// (`Uint8Array` in JS). Passing raw bytes prevents immutable V8 string persistence in JavaScript memory.
/// In Rust, all key buffers and signing structures are securely zeroized using the `zeroize` crate
/// immediately after signature generation.
#[wasm_bindgen(js_name = createSweepTransaction)]
pub fn create_sweep_transaction(
    utxos_json: &str,
    destination_address: &str,
    fee_sats: u64,
    network: &str,
    send_amount_sats: Option<u64>,
    change_address: Option<String>,
    spending_keys: Option<Vec<u8>>,
) -> Result<String, Error> {
    let mut spending_keys = spending_keys.map(Zeroizing::new);

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

    if let Some(ref keys) = spending_keys {
        if keys.len() != utxos.len() * 32 {
            return Err(Error::Generic(format!(
                "Invalid spending_keys length: expected {} bytes ({} UTXOs * 32), got {}",
                utxos.len() * 32,
                utxos.len(),
                keys.len()
            )));
        }
    }

    let mut pset = PartiallySignedTransaction::new_v2();
    set_genesis_hash(&mut pset, &net);

    let mut total_sats: u64 = 0;
    let mut inp_txout_sec: HashMap<usize, TxOutSecrets> = HashMap::with_capacity(utxos.len());
    let mut input_signers = Vec::with_capacity(utxos.len());
    let mut rng = thread_rng();

    for (idx, mut utxo) in utxos.into_iter().enumerate() {
        let txid = Txid::from_str(&utxo.txid)
            .map_err(|e| Error::Generic(format!("Invalid txid: {e}")))?;
        let outpoint = OutPoint::new(txid, utxo.vout);

        let asset_id = AssetId::from_str(&utxo.asset_id)
            .map_err(|e| Error::Generic(format!("Invalid asset_id: {e}")))?;
        let abf = AssetBlindingFactor::from_str(&utxo.asset_blinding_factor)
            .map_err(|e| Error::Generic(format!("Invalid asset_blinding_factor: {e}")))?;
        let vbf = ValueBlindingFactor::from_str(&utxo.value_blinding_factor)
            .map_err(|e| Error::Generic(format!("Invalid value_blinding_factor: {e}")))?;

        // Extract 32-byte private key: prefer raw bytes from spending_keys, fallback to legacy hex in utxo
        let zeroizing_key: Zeroizing<[u8; 32]> = if let Some(ref keys) = spending_keys {
            let mut key_buf = [0u8; 32];
            key_buf.copy_from_slice(&keys[idx * 32..(idx + 1) * 32]);
            Zeroizing::new(key_buf)
        } else if let Some(mut hex_key) = utxo.spending_private_key.take() {
            let mut privkey_bytes = Vec::<u8>::from_hex(&hex_key)
                .map_err(|e| Error::Generic(format!("Invalid spending_private_key hex: {e}")))?;
            hex_key.zeroize();
            if privkey_bytes.len() != 32 {
                privkey_bytes.zeroize();
                return Err(Error::Generic("spending_private_key must be 32 bytes".to_string()));
            }
            let mut key_buf = [0u8; 32];
            key_buf.copy_from_slice(&privkey_bytes);
            privkey_bytes.zeroize();
            Zeroizing::new(key_buf)
        } else {
            return Err(Error::Generic(format!(
                "Missing spending private key for UTXO at index {idx} (neither raw spending_keys nor spendingPrivateKey JSON provided)"
            )));
        };

        let is_p2wpkh = utxo
            .script_type
            .as_deref()
            .map(|s| s.eq_ignore_ascii_case("p2wpkh"))
            .unwrap_or(false);

        let spk = if is_p2wpkh {
            let sec_key = SecretKey::from_slice(&*zeroizing_key)
                .map_err(|e| Error::Generic(format!("Invalid spending private key: {e}")))?;
            let secp_pk = SecpPublicKey::from_secret_key(&EC, &sec_key);
            let pk_hash = Hash160::hash(&secp_pk.serialize());
            let mut spk_bytes = vec![0x00, 0x14];
            spk_bytes.extend_from_slice(pk_hash.as_byte_array());
            input_signers.push(InputSigner::SegwitV0(zeroizing_key, secp_pk));
            Script::from(spk_bytes)
        } else {
            let keypair = Keypair::from_seckey_slice(&EC, &*zeroizing_key)
                .map_err(|e| Error::Generic(format!("Invalid spending private key: {e}")))?;
            let (xonly_pk, _parity) = XOnlyPublicKey::from_keypair(&keypair);
            let mut spk_bytes = vec![0x51, 0x20];
            spk_bytes.extend_from_slice(&xonly_pk.serialize());
            input_signers.push(InputSigner::Taproot(zeroizing_key));
            Script::from(spk_bytes)
        };

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
        total_sats += utxo.amount_sats;
    }

    // Zeroize the raw spending_keys buffer in WASM memory now that keys are transferred into input_signers
    if let Some(ref mut keys) = spending_keys {
        keys.zeroize();
    }

    if total_sats <= fee_sats {
        return Err(Error::Generic(format!(
            "Total input amount ({total_sats} sats) is less than or equal to fee ({fee_sats} sats)"
        )));
    }
    let max_send = total_sats - fee_sats;
    let (send_sats, change_sats, final_fee_sats) = match send_amount_sats {
        Some(0) => {
            return Err(Error::Generic("Send amount cannot be 0 sats".into()));
        }
        Some(amt) if amt < max_send => {
            let change = max_send - amt;
            if change < DUST_LIMIT_SATS {
                // Change is below dust threshold: absorb into miner fee instead of creating
                // an uneconomical output that Liquid nodes would reject as dust.
                (amt, None, fee_sats + change)
            } else {
                (amt, Some(change), fee_sats)
            }
        }
        Some(amt) if amt == max_send => (max_send, None, fee_sats),
        Some(amt) => {
            return Err(Error::Generic(format!(
                "Send amount ({amt} sats) exceeds available balance ({max_send} sats after {fee_sats} fee)"
            )));
        }
        None => (max_send, None, fee_sats),
    };

    let dest_output = Output {
        script_pubkey: dest_script,
        amount: Some(send_sats),
        asset: Some(*policy_asset),
        blinding_key: dest_blinding_pk.map(lwk_wollet::bitcoin::PublicKey::new),
        blinder_index: if dest_blinding_pk.is_some() { Some(0) } else { None },
        ..Default::default()
    };
    pset.add_output(dest_output);

    if let Some(chg_sats) = change_sats {
        let chg_addr_str = change_address.as_deref().ok_or_else(|| {
            Error::Generic("Change address must be provided for partial spend".to_string())
        })?;
        let chg_addr = Address::from_str(chg_addr_str)
            .map_err(|e| Error::Generic(format!("Invalid change address: {e}")))?;
        let chg_script = chg_addr.script_pubkey();
        let chg_blinding_pk = chg_addr.blinding_pubkey;

        let change_output = Output {
            script_pubkey: chg_script,
            amount: Some(chg_sats),
            asset: Some(*policy_asset),
            blinding_key: chg_blinding_pk.map(lwk_wollet::bitcoin::PublicKey::new),
            blinder_index: if chg_blinding_pk.is_some() { Some(0) } else { None },
            ..Default::default()
        };
        pset.add_output(change_output);
    }

    let fee_output = Output {
        script_pubkey: Script::default(),
        amount: Some(final_fee_sats),
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

    for (i, signer) in input_signers.iter().enumerate() {
        let msg = pset
            .sighash_msg(i, &mut sighash_cache, None, genesis_hash)
            .map_err(|e| Error::Generic(format!("sighash_msg error: {e}")))?;
        let secp_msg = msg.to_secp_msg();
        match signer {
            InputSigner::Taproot(key_bytes) => {
                let keypair = Keypair::from_seckey_slice(&EC, &**key_bytes)
                    .map_err(|e| Error::Generic(format!("Signing error (Taproot keypair): {e}")))?;
                let sig = EC.sign_schnorr(&secp_msg, &keypair);
                pset.inputs_mut()[i].final_script_witness = Some(vec![sig.as_ref().to_vec()]);
            }
            InputSigner::SegwitV0(key_bytes, pubkey) => {
                let sec_key = SecretKey::from_slice(&**key_bytes)
                    .map_err(|e| Error::Generic(format!("Signing error (Segwit secret key): {e}")))?;
                let sig = EC.sign_ecdsa(&secp_msg, &sec_key);
                let mut sig_bytes = sig.serialize_der().to_vec();
                sig_bytes.push(0x01); // SIGHASH_ALL
                pset.inputs_mut()[i].final_script_witness =
                    Some(vec![sig_bytes, pubkey.serialize().to_vec()]);
            }
        }
    }

    // Zeroize all private key material stored in input_signers immediately after signing!
    drop(input_signers);

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
        let tx_hex = create_sweep_transaction(utxo_json, dest_address, fee_sats, "testnet", None, None, None).unwrap();
        assert!(!tx_hex.is_empty());
        let tx_bytes = Vec::<u8>::from_hex(&tx_hex).unwrap();
        let tx: lwk_wollet::elements::Transaction = lwk_wollet::elements::encode::deserialize(&tx_bytes).unwrap();
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 2);
        assert!(tx.output[0].witness.rangeproof.is_some());
        assert!(tx.output[0].witness.surjection_proof.is_some());
        assert!(tx.output[1].is_fee());
        assert_eq!(tx.output[1].minimum_value(), fee_sats);
        assert_eq!(tx.input[0].witness.script_witness.len(), 1);
        assert_eq!(tx.input[0].witness.script_witness[0].len(), 64);
    }

    #[test]
    fn test_create_partial_sweep_transaction() {
        let dest_address = "tlq1qq2xvpcvfup5j8zscjq05u2wxxjcyewk7979f3mmz5l7uw5pqmx6xf5xy50hsn6vhkm5euwt72x878eq6zxx2z58hd7zrsg9qn";
        let change_address = "tlq1qq2xvpcvfup5j8zscjq05u2wxxjcyewk7979f3mmz5l7uw5pqmx6xf5xy50hsn6vhkm5euwt72x878eq6zxx2z58hd7zrsg9qn";
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
        let send_sats = 40000;
        let tx_hex = create_sweep_transaction(
            utxo_json,
            dest_address,
            fee_sats,
            "testnet",
            Some(send_sats),
            Some(change_address.to_string()),
            None,
        ).unwrap();

        assert!(!tx_hex.is_empty());
        let tx_bytes = Vec::<u8>::from_hex(&tx_hex).unwrap();
        let tx: lwk_wollet::elements::Transaction = lwk_wollet::elements::encode::deserialize(&tx_bytes).unwrap();
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 3); // output 0: send_sats, output 1: change (59500), output 2: fee (500)
        assert!(tx.output[0].witness.rangeproof.is_some());
        assert!(tx.output[0].witness.surjection_proof.is_some());
        assert!(tx.output[1].witness.rangeproof.is_some());
        assert!(tx.output[1].witness.surjection_proof.is_some());
        assert!(tx.output[2].is_fee());
        assert_eq!(tx.output[2].minimum_value(), fee_sats);
        assert_eq!(tx.input[0].witness.script_witness.len(), 1);
        assert_eq!(tx.input[0].witness.script_witness[0].len(), 64);
    }

    #[test]
    fn test_create_partial_sweep_dust_change_absorbed() {
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
        let send_sats = 99200;
        let tx_hex = create_sweep_transaction(
            utxo_json,
            dest_address,
            fee_sats,
            "testnet",
            Some(send_sats),
            None,
            None,
        ).unwrap();

        assert!(!tx_hex.is_empty());
        let tx_bytes = Vec::<u8>::from_hex(&tx_hex).unwrap();
        let tx: lwk_wollet::elements::Transaction = lwk_wollet::elements::encode::deserialize(&tx_bytes).unwrap();
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 2); // Only recipient + fee, NO change output
        assert!(tx.output[0].witness.rangeproof.is_some());
        assert!(tx.output[1].is_fee());
        assert_eq!(tx.output[1].minimum_value(), 800); // 500 + 300 dust change absorbed
    }

    #[test]
    fn test_create_sweep_transaction_raw_bytes() {
        let dest_address = "tlq1qq2xvpcvfup5j8zscjq05u2wxxjcyewk7979f3mmz5l7uw5pqmx6xf5xy50hsn6vhkm5euwt72x878eq6zxx2z58hd7zrsg9qn";
        // Notice: NO spendingPrivateKey in JSON!
        let utxo_json = r#"[
            {
                "txid": "0000000000000000000000000000000000000000000000000000000000000001",
                "vout": 0,
                "amountSats": 100000,
                "assetId": "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49",
                "assetBlindingFactor": "0000000000000000000000000000000000000000000000000000000000000002",
                "valueBlindingFactor": "0000000000000000000000000000000000000000000000000000000000000003",
                "scriptType": "p2tr"
            },
            {
                "txid": "0000000000000000000000000000000000000000000000000000000000000002",
                "vout": 1,
                "amountSats": 50000,
                "assetId": "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49",
                "assetBlindingFactor": "0000000000000000000000000000000000000000000000000000000000000002",
                "valueBlindingFactor": "0000000000000000000000000000000000000000000000000000000000000003",
                "scriptType": "p2wpkh"
            }
        ]"#;

        // Raw 32-byte private keys concatenated (64 bytes total for 2 UTXOs)
        let mut raw_keys = vec![0u8; 64];
        raw_keys[31] = 0x04; // Key 0: scalar 4
        raw_keys[63] = 0x05; // Key 1: scalar 5

        let fee_sats = 600;
        let tx_hex = create_sweep_transaction(
            utxo_json,
            dest_address,
            fee_sats,
            "testnet",
            None,
            None,
            Some(raw_keys.clone()),
        ).unwrap();

        assert!(!tx_hex.is_empty());
        let tx_bytes = Vec::<u8>::from_hex(&tx_hex).unwrap();
        let tx: lwk_wollet::elements::Transaction = lwk_wollet::elements::encode::deserialize(&tx_bytes).unwrap();
        assert_eq!(tx.input.len(), 2);
        // Input 0 (p2tr): 1 witness item (64-byte Schnorr sig)
        assert_eq!(tx.input[0].witness.script_witness.len(), 1);
        assert_eq!(tx.input[0].witness.script_witness[0].len(), 64);
        // Input 1 (p2wpkh): 2 witness items (DER sig + 33-byte compressed pubkey)
        assert_eq!(tx.input[1].witness.script_witness.len(), 2);
        assert_eq!(tx.input[1].witness.script_witness[1].len(), 33);

        // Validation: wrong key length must return an error
        let wrong_keys = vec![0u8; 32]; // only 32 bytes for 2 UTXOs
        let err = create_sweep_transaction(
            utxo_json,
            dest_address,
            fee_sats,
            "testnet",
            None,
            None,
            Some(wrong_keys),
        );
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("Invalid spending_keys length"));
    }

    #[test]
    fn test_estimate_sweep_vsize_segwit_vs_taproot() {
        // 1 P2TR input, no change: 1225 + 58 = 1283
        assert_eq!(estimate_sweep_vsize(1, None, None), 1283);
        assert_eq!(estimate_sweep_vsize(1, Some(false), Some(0)), 1283);

        // 1 P2WPKH input, no change: 1225 + 69 = 1294
        assert_eq!(estimate_sweep_vsize(1, Some(false), Some(1)), 1294);

        // 1 P2TR input + change: 1225 + 280 + 58 = 1563
        assert_eq!(estimate_sweep_vsize(1, Some(true), None), 1563);

        // 2 inputs (1 P2TR + 1 P2WPKH), with change: 1225 + 280 + 58 + 69 = 1632
        assert_eq!(estimate_sweep_vsize(2, Some(true), Some(1)), 1632);
    }
}
