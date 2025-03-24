library;

use std::constants::ZERO_B256;

/// Personal sign prefix for Fuel inclusive of the 32 bytes for the length of the message.
///
/// # Additional Information
///
/// Take "\x19Fuel Signed Message:\n32" and converted to hex.
/// The 0000000000000000 at the end is the padding added by Sway to fill the word.
const FUEL_PERSONAL_SIGNATURE_PREFIX = 0x194675656c205369676e6564204d6573736167653a0a33320000000000000000;

struct SignedData {
    /// The message to sign.
    message: b256,
    /// EIP-191 personal sign prefix.
    fuel_personal_sig_prefix: b256,
    /// Additional data used for reserving memory for hashing (hack).
    #[allow(dead_code)]
    empty: b256,
}

/// Applies EIP-191 personal sign hashing of the given `message`.
///
/// # Arguments
///
/// * `message`: [b256] - The data to be hashed.
///
/// # Returns
///
/// * [b256] - The personal sign hash of the `message`.
pub fn personal_sign_hash(message: b256) -> b256 {
    // Hack, allocate memory to reduce manual `asm` code.
    let data = SignedData {
        message,
        fuel_personal_sig_prefix: FUEL_PERSONAL_SIGNATURE_PREFIX,
        empty: ZERO_B256,
    };

    // Pointer to the data we have signed external to Sway.
    let data_ptr = asm(ptr: data.message) {
        ptr
    };

    // The Fuel personal signature prefix is 24 bytes (plus padding we exclude).
    // The message is 32 bytes at the end of the prefix.
    let len_to_hash = 24 + 32;

    // Create a buffer in memory to overwrite with the result being the hash.
    let mut buffer = b256::min();

    // Copy the message to the end of the prefix and hash the exact len of the prefix and id (without
    // the padding at the end because that would alter the hash).
    asm(
        hash: buffer,
        msg_id: data_ptr,
        end_of_prefix: data_ptr + len_to_hash,
        prefix: data.fuel_personal_sig_prefix,
        id_len: 32,
        hash_len: len_to_hash,
    ) {
        mcp end_of_prefix msg_id id_len;
        s256 hash prefix hash_len;
    }

    // The buffer contains the hash.
    buffer
}
