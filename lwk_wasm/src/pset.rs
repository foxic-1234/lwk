use crate::{AssetId, Error, Issuance, Script, Transaction, Txid, Wollet};
#[cfg(feature = "simplicity")]
use crate::{ContractHash, LockTime, OutPoint, PublicKey, Tweak, TxOut, TxOutSecrets, TxSequence};
use lwk_wollet::elements_miniscript::psbt::PsbtExt;

#[cfg(feature = "simplicity")]
use std::collections::HashMap;
use std::fmt::Display;

#[cfg(feature = "simplicity")]
use lwk_wollet::elements::hashes::Hash;
use lwk_wollet::elements::pset::{Input, Output, PartiallySignedTransaction};
#[cfg(feature = "simplicity")]
use lwk_wollet::elements::BlockHash;
#[cfg(feature = "simplicity")]
use lwk_wollet::elements_miniscript::psbt::finalize;
#[cfg(feature = "simplicity")]
use lwk_wollet::secp256k1::rand::thread_rng;
#[cfg(feature = "simplicity")]
use lwk_wollet::EC;

use wasm_bindgen::prelude::*;

/// Partially Signed Elements Transaction
#[wasm_bindgen]
#[derive(PartialEq, Debug, Clone)]
pub struct Pset {
    inner: PartiallySignedTransaction,
}

impl From<PartiallySignedTransaction> for Pset {
    fn from(inner: PartiallySignedTransaction) -> Self {
        Self { inner }
    }
}

impl From<Pset> for PartiallySignedTransaction {
    fn from(pset: Pset) -> Self {
        pset.inner
    }
}

impl Display for Pset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

#[wasm_bindgen]
impl Pset {
    /// Creates a `Pset` from its base64 string representation.
    #[wasm_bindgen(constructor)]
    pub fn new(base64: &str) -> Result<Pset, Error> {
        if base64.trim().is_empty() {
            return Err(Error::Generic("Empty pset".to_string()));
        }
        let pset: PartiallySignedTransaction = base64.trim().parse()?;
        Ok(pset.into())
    }

    /// Return a base64 string representation of the Pset.
    /// The string can be used to re-create the Pset via `new()`
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string_js(&self) -> String {
        format!("{self}")
    }

    /// Extract the Transaction from a Pset by filling in
    /// the available signature information in place.
    #[wasm_bindgen(js_name = extractTx)]
    pub fn extract_tx(&self) -> Result<Transaction, Error> {
        let tx: Transaction = self.inner.extract_tx()?.into();
        Ok(tx)
    }

    /// Get the unique id of the PSET as defined by [BIP-370](https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki#unique-identification)
    ///
    /// The unique id is the txid of the PSET with sequence numbers of inputs set to 0
    #[wasm_bindgen(js_name = uniqueId)]
    pub fn unique_id(&self) -> Result<crate::Txid, Error> {
        let txid = self.inner.unique_id()?;
        Ok(txid.into())
    }

    /// Attempt to merge with another `Pset`.
    pub fn combine(&mut self, other: Pset) -> Result<(), Error> {
        self.inner.merge(other.into())?;
        Ok(())
    }

    /// Return a copy of the inputs of this PSET
    pub fn inputs(&self) -> Vec<PsetInput> {
        self.inner.inputs().iter().map(Into::into).collect()
    }

    /// Return a copy of the outputs of this PSET
    pub fn outputs(&self) -> Vec<PsetOutput> {
        self.inner.outputs().iter().map(Into::into).collect()
    }

    /// Add wallet details to this PSET in place
    #[wasm_bindgen(js_name = addDetails)]
    pub fn add_details(&mut self, wollet: &Wollet) -> Result<(), Error> {
        wollet.inner().add_details(&mut self.inner)?;
        Ok(())
    }

    /// Sign a BIP-341 key-path input by index with a 32-byte secret key.
    ///
    /// The input's `witness_utxo` must be a v1 P2TR output whose output key is `secret_key·G`
    /// (no taptweak is applied: BIP-352 outputs commit to the key directly). The signature is
    /// verified against that output key before the final witness is written.
    ///
    /// The PSET must carry the genesis block hash (ELIP-101), as PSETs built by `TxBuilder` do:
    /// it is part of the Elements Taproot sighash.
    #[wasm_bindgen(js_name = signTaprootKeypath)]
    pub fn sign_taproot_keypath(&mut self, index: usize, secret_key: &[u8]) -> Result<(), Error> {
        use lwk_wollet::elements::secp256k1_zkp::{Keypair, XOnlyPublicKey};

        let input = self
            .inner
            .inputs()
            .get(index)
            .ok_or_else(|| Error::Generic(format!("Input index {index} out of bounds")))?;
        let spk = &input
            .witness_utxo
            .as_ref()
            .ok_or_else(|| Error::Generic(format!("Input {index} has no witness_utxo")))?
            .script_pubkey;
        if !spk.is_v1_p2tr() {
            return Err(Error::Generic(format!(
                "Input {index} is not a v1 P2TR output"
            )));
        }
        let output_key = XOnlyPublicKey::from_slice(&spk.as_bytes()[2..34])
            .map_err(|e| Error::Generic(format!("Invalid Taproot output key: {e}")))?;
        let genesis_hash = pset_genesis_hash(&self.inner)?;

        let mut keypair = Keypair::from_seckey_slice(&lwk_wollet::EC, secret_key)
            .map_err(|e| Error::Generic(format!("Invalid private key: {e}")))?;
        let result = (|| {
            if keypair.x_only_public_key().0 != output_key {
                return Err(Error::Generic(format!(
                    "Secret key does not match the Taproot output key of input {index}"
                )));
            }

            let tx = self
                .inner
                .extract_tx()
                .map_err(|e| Error::Generic(format!("extract_tx error before sign: {e}")))?;
            let mut sighash_cache = lwk_wollet::elements::sighash::SighashCache::new(&tx);
            let msg = self
                .inner
                .sighash_msg(index, &mut sighash_cache, None, genesis_hash)
                .map_err(|e| Error::Generic(format!("sighash_msg error: {e}")))?
                .to_secp_msg();
            let sig = lwk_wollet::EC.sign_schnorr(&msg, &keypair);
            lwk_wollet::EC
                .verify_schnorr(&sig, &msg, &output_key)
                .map_err(|e| Error::Generic(format!("Schnorr self-verification failed: {e}")))?;
            Ok(sig)
        })();
        keypair.non_secure_erase();

        self.inner.inputs_mut()[index].final_script_witness = Some(vec![result?.as_ref().to_vec()]);
        Ok(())
    }
}

/// Read the genesis block hash from the PSET global proprietary field (ELIP-101).
///
/// Fails rather than defaulting to zeros: a wrong genesis hash yields a signature that passes
/// self-verification against the same sighash yet is invalid on chain.
fn pset_genesis_hash(
    pset: &PartiallySignedTransaction,
) -> Result<lwk_wollet::elements::BlockHash, Error> {
    use lwk_wollet::elements::hashes::Hash as _;
    use lwk_wollet::elements::pset::raw::ProprietaryKey;

    const PSBT_ELEMENTS_GLOBAL_GENESIS_HASH: u8 = 0x02;
    let key = ProprietaryKey::from_pset_pair(PSBT_ELEMENTS_GLOBAL_GENESIS_HASH, vec![]);
    let bytes: [u8; 32] = pset
        .global
        .proprietary
        .get(&key)
        .and_then(|v| v.as_slice().try_into().ok())
        .ok_or_else(|| Error::Generic("PSET has no genesis block hash (ELIP-101)".to_string()))?;
    Ok(lwk_wollet::elements::BlockHash::from_byte_array(bytes))
}

#[cfg(feature = "simplicity")]
#[wasm_bindgen]
impl Pset {
    /// Finalize and extract the PSET
    pub fn finalize(&self) -> Result<Transaction, Error> {
        let mut pset = self.inner.clone();
        finalize(&mut pset, &EC, BlockHash::all_zeros())?;
        let tx: Transaction = pset.extract_tx()?.into();
        Ok(tx)
    }
}

impl Pset {
    // TODO(KyrylR): remove dead_code after all Simplicity features are added
    #[allow(dead_code)]
    pub(crate) fn inner(&self) -> &PartiallySignedTransaction {
        &self.inner
    }
}

/// PSET input
#[wasm_bindgen]
pub struct PsetInput {
    inner: Input,
}

impl From<&Input> for PsetInput {
    fn from(inner: &Input) -> Self {
        Self {
            inner: inner.clone(),
        }
    }
}

impl From<Input> for PsetInput {
    fn from(inner: Input) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen]
impl PsetInput {
    /// Prevout TXID of the input
    #[wasm_bindgen(js_name = previousTxid)]
    pub fn previous_txid(&self) -> Txid {
        self.inner.previous_txid.into()
    }

    /// Prevout vout of the input
    #[wasm_bindgen(js_name = previousVout)]
    pub fn previous_vout(&self) -> u32 {
        self.inner.previous_output_index
    }

    /// Prevout scriptpubkey of the input
    #[wasm_bindgen(js_name = previousScriptPubkey)]
    pub fn previous_script_pubkey(&self) -> Option<Script> {
        self.inner
            .witness_utxo
            .as_ref()
            .map(|txout| txout.script_pubkey.clone().into())
    }

    /// Redeem script of the input
    #[wasm_bindgen(js_name = redeemScript)]
    pub fn redeem_script(&self) -> Option<Script> {
        self.inner.redeem_script.as_ref().map(|s| s.clone().into())
    }

    /// If the input has an issuance, the asset id
    #[wasm_bindgen(js_name = issuanceAsset)]
    pub fn issuance_asset(&self) -> Option<AssetId> {
        self.inner
            .has_issuance()
            .then(|| self.inner.issuance_ids().0.into())
    }

    /// If the input has an issuance, the token id
    #[wasm_bindgen(js_name = issuanceToken)]
    pub fn issuance_token(&self) -> Option<AssetId> {
        self.inner
            .has_issuance()
            .then(|| self.inner.issuance_ids().1.into())
    }

    /// If the input has a (re)issuance, the issuance object
    pub fn issuance(&self) -> Option<Issuance> {
        self.inner
            .has_issuance()
            .then(|| lwk_common::Issuance::new(&self.inner).into())
    }

    /// Input sighash
    pub fn sighash(&self) -> u32 {
        self.inner.sighash_type.map(|s| s.to_u32()).unwrap_or(1)
    }

    /// If the input has an issuance, returns [asset_id, token_id].
    /// Returns undefined if the input has no issuance.
    #[wasm_bindgen(js_name = issuanceIds)]
    pub fn issuance_ids(&self) -> Option<Vec<AssetId>> {
        self.inner.has_issuance().then(|| {
            let (asset, token) = self.inner.issuance_ids();
            vec![asset.into(), token.into()]
        })
    }
}

#[cfg(feature = "simplicity")]
impl PsetInput {
    pub(crate) fn inner(&self) -> &Input {
        &self.inner
    }
}

#[cfg(feature = "simplicity")]
/// Builder for PSET inputs
#[wasm_bindgen]
pub struct PsetInputBuilder {
    inner: Input,
}

#[cfg(feature = "simplicity")]
#[wasm_bindgen]
impl PsetInputBuilder {
    /// Construct a PsetInputBuilder from an outpoint.
    #[wasm_bindgen(js_name = fromPrevout)]
    pub fn from_prevout(outpoint: &OutPoint) -> PsetInputBuilder {
        PsetInputBuilder {
            inner: Input::from_prevout(outpoint.into()),
        }
    }

    /// Set the witness UTXO.
    #[wasm_bindgen(js_name = witnessUtxo)]
    pub fn witness_utxo(mut self, utxo: &TxOut) -> PsetInputBuilder {
        self.inner.witness_utxo = Some(utxo.into());
        self
    }

    /// Set the sequence number.
    pub fn sequence(mut self, sequence: &TxSequence) -> PsetInputBuilder {
        self.inner.sequence = Some(sequence.into());
        self
    }

    /// Set the issuance value amount.
    #[wasm_bindgen(js_name = issuanceValueAmount)]
    pub fn issuance_value_amount(mut self, amount: u64) -> PsetInputBuilder {
        self.inner.issuance_value_amount = Some(amount);
        self
    }

    /// Set the issuance inflation keys.
    #[wasm_bindgen(js_name = issuanceInflationKeys)]
    pub fn issuance_inflation_keys(mut self, amount: u64) -> PsetInputBuilder {
        self.inner.issuance_inflation_keys = Some(amount);
        self
    }

    /// Set the issuance asset entropy.
    #[wasm_bindgen(js_name = issuanceAssetEntropy)]
    pub fn issuance_asset_entropy(mut self, contract_hash: &ContractHash) -> PsetInputBuilder {
        let inner_hash: lwk_wollet::elements::ContractHash = contract_hash.into();
        self.inner.issuance_asset_entropy = Some(inner_hash.to_byte_array());
        self
    }

    /// Set the blinded issuance flag.
    #[wasm_bindgen(js_name = blindedIssuance)]
    pub fn blinded_issuance(mut self, flag: bool) -> PsetInputBuilder {
        self.inner.blinded_issuance = Some(u8::from(flag));
        self
    }

    /// Set the issuance blinding nonce.
    #[wasm_bindgen(js_name = issuanceBlindingNonce)]
    pub fn issuance_blinding_nonce(mut self, nonce: &Tweak) -> PsetInputBuilder {
        self.inner.issuance_blinding_nonce = Some(nonce.into());
        self
    }

    /// Build the PsetInput, consuming the builder.
    pub fn build(self) -> PsetInput {
        PsetInput::from(self.inner)
    }
}

/// PSET output
#[wasm_bindgen]
pub struct PsetOutput {
    inner: Output,
}

impl From<&Output> for PsetOutput {
    fn from(inner: &Output) -> Self {
        Self {
            inner: inner.clone(),
        }
    }
}

impl From<Output> for PsetOutput {
    fn from(inner: Output) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen]
impl PsetOutput {
    /// Get the script pubkey
    #[wasm_bindgen(js_name = scriptPubkey)]
    pub fn script_pubkey(&self) -> Script {
        self.inner.script_pubkey.clone().into()
    }

    /// Get the explicit amount, if set
    pub fn amount(&self) -> Option<u64> {
        self.inner.amount
    }

    /// Get the explicit asset ID, if set
    pub fn asset(&self) -> Option<AssetId> {
        self.inner.asset.map(Into::into)
    }

    /// Get the blinder index, if set
    #[wasm_bindgen(js_name = blinderIndex)]
    pub fn blinder_index(&self) -> Option<u32> {
        self.inner.blinder_index
    }
}

#[cfg(feature = "simplicity")]
impl PsetOutput {
    pub(crate) fn inner(&self) -> &Output {
        &self.inner
    }
}

#[cfg(feature = "simplicity")]
/// Builder for PSET outputs
#[wasm_bindgen]
pub struct PsetOutputBuilder {
    inner: Output,
}

#[cfg(feature = "simplicity")]
#[wasm_bindgen]
impl PsetOutputBuilder {
    /// Construct a PsetOutputBuilder with explicit asset and value.
    #[wasm_bindgen(js_name = newExplicit)]
    pub fn new_explicit(
        script_pubkey: &Script,
        satoshi: u64,
        asset: &AssetId,
    ) -> PsetOutputBuilder {
        let output = Output {
            script_pubkey: script_pubkey.as_ref().clone(),
            amount: Some(satoshi),
            asset: Some((*asset).into()),
            ..Default::default()
        };
        PsetOutputBuilder { inner: output }
    }

    /// Set the blinding public key.
    #[wasm_bindgen(js_name = blindingPubkey)]
    pub fn blinding_pubkey(mut self, blinding_key: &PublicKey) -> PsetOutputBuilder {
        self.inner.blinding_key = Some(blinding_key.into());
        self
    }

    /// Set the script pubkey.
    #[wasm_bindgen(js_name = scriptPubkey)]
    pub fn script_pubkey(mut self, script_pubkey: &Script) -> PsetOutputBuilder {
        self.inner.script_pubkey = script_pubkey.as_ref().clone();
        self
    }

    /// Set the explicit amount.
    pub fn satoshi(mut self, satoshi: u64) -> PsetOutputBuilder {
        self.inner.amount = Some(satoshi);
        self
    }

    /// Set the explicit asset ID.
    pub fn asset(mut self, asset: &AssetId) -> PsetOutputBuilder {
        self.inner.asset = Some((*asset).into());
        self
    }

    /// Set the blinder index.
    #[wasm_bindgen(js_name = blinderIndex)]
    pub fn blinder_index(mut self, index: u32) -> PsetOutputBuilder {
        self.inner.blinder_index = Some(index);
        self
    }

    /// Build the PsetOutput, consuming the builder.
    pub fn build(self) -> PsetOutput {
        PsetOutput::from(self.inner)
    }
}

#[cfg(feature = "simplicity")]
/// Builder for constructing a PSET from scratch
#[wasm_bindgen]
pub struct PsetBuilder {
    inner: PartiallySignedTransaction,
}

#[cfg(feature = "simplicity")]
#[wasm_bindgen]
impl PsetBuilder {
    /// Create a new PSET v2 builder
    #[wasm_bindgen(js_name = newV2)]
    pub fn new_v2() -> PsetBuilder {
        PsetBuilder {
            inner: PartiallySignedTransaction::new_v2(),
        }
    }

    /// Add an input to this PSET
    #[wasm_bindgen(js_name = addInput)]
    pub fn add_input(mut self, input: &PsetInput) -> PsetBuilder {
        self.inner.add_input(input.inner().clone());
        self
    }

    /// Add an output to this PSET
    #[wasm_bindgen(js_name = addOutput)]
    pub fn add_output(mut self, output: &PsetOutput) -> PsetBuilder {
        self.inner.add_output(output.inner().clone());
        self
    }

    /// Set the fallback locktime on the PSET global tx_data
    #[wasm_bindgen(js_name = setFallbackLocktime)]
    pub fn set_fallback_locktime(mut self, locktime: &LockTime) -> PsetBuilder {
        self.inner.global.tx_data.fallback_locktime = Some(locktime.into());
        self
    }

    /// Blind the last output using the provided input secrets.
    ///
    /// `inp_txout_sec` is a map from input index to TxOutSecrets, represented as
    /// parallel arrays where `input_indices[i]` corresponds to `secrets[i]`.
    ///
    /// NOTE: The secrets object is destroyed during the execution of the function, so the argument that was
    /// passed in the JS code cannot be reused.
    // TODO: address the limitation
    #[wasm_bindgen(js_name = blindLast)]
    pub fn blind_last(
        mut self,
        input_indices: &[u32],
        secrets: Vec<TxOutSecrets>,
    ) -> Result<PsetBuilder, Error> {
        if input_indices.len() != secrets.len() {
            return Err(Error::Generic(format!(
                "input_indices length ({}) must match secrets length ({})",
                input_indices.len(),
                secrets.len()
            )));
        }

        let mut inp_txout_sec: HashMap<usize, lwk_wollet::elements::TxOutSecrets> =
            HashMap::with_capacity(input_indices.len());
        for (&index, secret) in input_indices.iter().zip(secrets.iter()) {
            if inp_txout_sec
                .insert(index as usize, secret.into())
                .is_some()
            {
                return Err(Error::Generic(format!(
                    "input_indices must be unique, duplicate index {index}"
                )));
            }
        }

        self.inner
            .blind_last(&mut thread_rng(), &EC, &inp_txout_sec)?;
        Ok(self)
    }

    /// Build the Pset, consuming the builder
    pub fn build(self) -> Pset {
        Pset::from(self.inner)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod taproot_keypath_tests {
    use super::*;
    use lwk_wollet::elements::confidential::{Asset, Nonce, Value};
    #[allow(unused_imports)] // also imported by `super::*` under the `simplicity` feature
    use lwk_wollet::elements::hashes::Hash as _;
    use lwk_wollet::elements::pset::raw::ProprietaryKey;
    use lwk_wollet::elements::secp256k1_zkp::{schnorr, Keypair, Message};
    use lwk_wollet::elements::sighash::SighashCache;
    use lwk_wollet::elements::{self, AssetId as ElementsAssetId, OutPoint, TxOut, TxOutWitness};

    const SECRET: [u8; 32] = [7u8; 32];

    fn p2tr_pset(secret: &[u8; 32], with_genesis: bool) -> Pset {
        let keypair = Keypair::from_seckey_slice(&lwk_wollet::EC, secret).unwrap();
        let mut spk = vec![0x51, 0x20];
        spk.extend_from_slice(&keypair.x_only_public_key().0.serialize());
        let asset = Asset::Explicit(ElementsAssetId::from_slice(&[1u8; 32]).unwrap());

        let mut pset = PartiallySignedTransaction::new_v2();
        let mut input = Input::from_prevout(OutPoint::new(elements::Txid::all_zeros(), 0));
        input.witness_utxo = Some(TxOut {
            asset,
            value: Value::Explicit(10_000),
            nonce: Nonce::Null,
            script_pubkey: elements::Script::from(spk),
            witness: TxOutWitness::default(),
        });
        pset.add_input(input);
        pset.add_output(Output::from_txout(TxOut {
            asset,
            value: Value::Explicit(10_000),
            nonce: Nonce::Null,
            script_pubkey: elements::Script::new(),
            witness: TxOutWitness::default(),
        }));
        if with_genesis {
            pset.global.proprietary.insert(
                ProprietaryKey::from_pset_pair(0x02, vec![]),
                lwk_common::Network::TestnetLiquid
                    .genesis_hash()
                    .to_byte_array()
                    .to_vec(),
            );
        }
        pset.into()
    }

    #[test]
    fn signs_and_verifies_against_the_output_key() {
        let mut pset = p2tr_pset(&SECRET, true);
        pset.sign_taproot_keypath(0, &SECRET).unwrap();

        let inner = pset.inner();
        let witness = inner.inputs()[0].final_script_witness.as_ref().unwrap();
        assert_eq!(witness.len(), 1);
        assert_eq!(
            witness[0].len(),
            64,
            "default sighash: bare 64-byte BIP-340 signature"
        );

        let tx = inner.extract_tx().unwrap();
        let mut cache = SighashCache::new(&tx);
        let genesis = lwk_common::Network::TestnetLiquid.genesis_hash();
        let msg: Message = inner
            .sighash_msg(0, &mut cache, None, genesis)
            .unwrap()
            .to_secp_msg();
        let key = Keypair::from_seckey_slice(&lwk_wollet::EC, &SECRET)
            .unwrap()
            .x_only_public_key()
            .0;
        let sig = schnorr::Signature::from_slice(&witness[0]).unwrap();
        lwk_wollet::EC.verify_schnorr(&sig, &msg, &key).unwrap();
    }

    #[test]
    fn refuses_a_pset_without_genesis_hash() {
        let mut pset = p2tr_pset(&SECRET, false);
        let err = pset.sign_taproot_keypath(0, &SECRET).unwrap_err();
        assert!(err.to_string().contains("genesis"), "{err}");
        assert!(pset.inner().inputs()[0].final_script_witness.is_none());
    }

    #[test]
    fn refuses_a_key_that_does_not_match_the_output() {
        let mut pset = p2tr_pset(&SECRET, true);
        let err = pset.sign_taproot_keypath(0, &[8u8; 32]).unwrap_err();
        assert!(err.to_string().contains("does not match"), "{err}");
        assert!(pset.inner().inputs()[0].final_script_witness.is_none());
    }

    #[test]
    fn refuses_a_non_taproot_input_and_an_out_of_range_index() {
        let mut pset = p2tr_pset(&SECRET, true);
        assert!(pset.sign_taproot_keypath(1, &SECRET).is_err());

        let mut inner: PartiallySignedTransaction = pset.into();
        inner.inputs_mut()[0]
            .witness_utxo
            .as_mut()
            .unwrap()
            .script_pubkey = elements::Script::from(
            vec![0x00, 0x14]
                .into_iter()
                .chain([0u8; 20])
                .collect::<Vec<u8>>(),
        );
        let mut pset: Pset = inner.into();
        let err = pset.sign_taproot_keypath(0, &SECRET).unwrap_err();
        assert!(err.to_string().contains("not a v1 P2TR"), "{err}");
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn pset_roundtrip() {
        let pset_string =
            include_str!("../../lwk_jade/test_data/pset_to_be_signed.base64").to_string();
        let pset = Pset::new(&pset_string).unwrap();

        let tx_expected =
            include_str!("../../lwk_jade/test_data/pset_to_be_signed_transaction.hex").to_string();
        let tx = pset.extract_tx().unwrap();
        assert_eq!(tx_expected, tx.to_string());

        assert_eq!(pset_string, pset.to_string());

        let pset_in = &pset.inputs()[0];
        assert_eq!(
            pset_in.previous_txid().to_string(),
            "0093c96a69e9ea00b5409611f23435b6639c157afa1c88cf18960715ea10116c"
        );
        assert_eq!(pset_in.previous_vout(), 0);
        assert!(pset_in.previous_script_pubkey().is_some());
        assert!(pset_in.redeem_script().is_none());

        assert!(pset_in.issuance_asset().is_none());
        assert!(pset_in.issuance_token().is_none());
    }

    #[cfg(feature = "simplicity")]
    #[wasm_bindgen_test]
    fn pset_builder() {
        let txid =
            Txid::new("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
        let outpoint = OutPoint::from_parts(&txid, 0);
        let input = PsetInputBuilder::from_prevout(&outpoint)
            .sequence(&TxSequence::zero())
            .build();
        assert_eq!(input.previous_vout(), 0);

        let script = Script::empty();
        let asset = AssetId::from_string(
            "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d",
        )
        .unwrap();
        let output = PsetOutputBuilder::new_explicit(&script, 1000, &asset)
            .blinder_index(0)
            .build();
        assert_eq!(output.amount(), Some(1000));
        assert_eq!(output.blinder_index(), Some(0));

        let locktime = LockTime::from_height(100).unwrap();
        let pset = PsetBuilder::new_v2()
            .add_input(&input)
            .add_output(&output)
            .set_fallback_locktime(&locktime)
            .build();
        assert_eq!(pset.inputs().len(), 1);
        assert_eq!(pset.outputs().len(), 1);
        assert_eq!(pset.outputs()[0].amount(), Some(1000));
        assert_eq!(
            pset.inner().global.tx_data.fallback_locktime,
            Some(lwk_wollet::elements::LockTime::from_consensus(100))
        );
    }
}
