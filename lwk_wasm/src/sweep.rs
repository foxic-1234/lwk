//! Taproot key-path signing for PSET inputs.

use crate::{Error, Pset};
use wasm_bindgen::prelude::*;

/// Sign a Taproot key-path input in a PSET using a 32-byte private key.
#[wasm_bindgen(js_name = signTaprootKeypathInput)]
pub fn sign_taproot_keypath_input(
    pset: &mut Pset,
    input_index: usize,
    private_key: &[u8],
) -> Result<(), Error> {
    pset.sign_taproot_keypath(input_index, private_key)
}
