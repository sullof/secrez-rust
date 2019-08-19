//! Encryption and Decryption using Blowfish with ECB mode.

use std::iter;
use std::str;
use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;
use sha2::{Sha256, Sha512, Digest};
use std::ffi::OsString;

use crypto::bcrypt_pbkdf::bcrypt_pbkdf;
use crypto::blowfish::Blowfish;
use crypto::symmetriccipher::{BlockEncryptor, BlockDecryptor};

use rustc_serialize::base64::{self, ToBase64, FromBase64};
use rustc_serialize::hex::{ToHex, FromHex};

const PADDING_BYTE: u8 = 2;

pub fn hex_to_base64(hex: String) -> String {
    return hex.from_hex().unwrap().to_base64(base64::STANDARD);
}

pub fn base64_to_hex(b64: String) -> String {
    return b64.from_base64().unwrap().to_hex();
}

pub fn string56_to_u8(mut str: &str) -> [u8; 56] {
    let mut ret: [u8; 56] = [0; 56];
    let str = str.as_bytes();
    for i in 0..56 {
        ret[i] = str[i];
    }
    ret
}

//pub fn bytes_to_u8(mut str: Vec<u8>) -> [u8; 56] {
//    let mut ret: [u8; 56] = [0; 56];
//    let str = str.as_bytes();
//    for i in 0..56 {
//        ret[i] = str[i];
//    }
//    ret
//}

/// Returns the encrypted input using the given key.
pub fn encrypt(key: &[u8; 56], input: &[u8]) -> String {
    let bytes = cipher_with(key, input, |blowfish, from, mut to| {
        blowfish.encrypt_block(&from, &mut to);
    });
    bytes.to_hex()
}

/// Returns the decrypted input using the given key.
pub fn decrypt(key: &[u8; 56], hex_input: &str) -> OsString {
    use std::u8;
    use std::str;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let mut input = Vec::with_capacity(hex_input.len());
    for chunk in hex_input.as_bytes().chunks(2) {
        // We already now that the chunk is utf-8 compliant as it comes
        // from a &str.
        let fragment = unsafe { str::from_utf8_unchecked(chunk) };
        let byte = u8::from_str_radix(fragment, 16).unwrap_or(0);
        input.push(byte);
    }

    let mut bytes = cipher_with(key, &input, |blowfish, from, mut to| {
        blowfish.decrypt_block(&from, &mut to);
    });
    if let Some(index) = bytes.iter().position(|&b| b == PADDING_BYTE) {
        // Go ahead and ignore all bytes after the null character (\0).
        bytes.truncate(index);
    }

    OsStr::from_bytes(&bytes).to_owned()
}

pub fn random_key() -> String {
    let mut rng = thread_rng();
    let mut bytes: [u8; 56] = [0; 56];
    for i in 0..56 {
        bytes[i] = rng.gen();
    }
    bytes.to_hex()
}

pub fn random_string(size: usize) -> String {
    let mut rng = thread_rng();
    let mut chars: String = iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .take(size)
        .collect();
    chars
}

pub fn sha_256(msg: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.input(msg.as_bytes());
    let hash = hasher.result();
    hex::encode(hash)
}

pub fn key_448_bit(msg: &str, salt: &str) -> [u8; 56]{
    let mut hasher = Sha512::new();
    let mut data = String::new();
    data.push_str(msg);
    data.push_str(salt);
    hasher.input(data.as_bytes());
    let hash = hasher.result();
    let result = hex::encode(hash);
    let mut key = result[..112].to_owned();
    string56_to_u8(&key)
}

pub fn derive_password(password: &str, salt: &str) -> String {
    let mut out = [0u8; 32];
    let salt_bytes;
    let password_hash;
    if salt.is_empty() {
        password_hash = sha_256(&password);
        salt_bytes = password_hash.as_bytes();
    } else {
        salt_bytes = salt.as_bytes();
    }
    bcrypt_pbkdf(password.as_bytes(), salt_bytes, 33, &mut out);
    let mut password_hash = String::with_capacity(out.len() * 2);
    for c in out.iter() {
        password_hash.push_str(&format!("{:02x}", c));
    }
    password_hash
}

/// Divides the input in blocks and cyphers using the given closure.
fn cipher_with<F>(key: &[u8], input: &[u8], mut func: F) -> Vec<u8>
    where F: FnMut(Blowfish, &mut [u8], &mut [u8]) {
    let blowfish = Blowfish::new(key);
    let block_size = <Blowfish as BlockEncryptor>::block_size(&blowfish);

    // Input and output bytes
    let input_len = round_len(input.len(), block_size);
    let mut input = input.to_vec();
    input.resize(input_len, PADDING_BYTE);

    let mut output: Vec<u8> = Vec::with_capacity(input_len);
    unsafe { output.set_len(input_len); }

    // Encrypts input and saves it into output
    for (ichunk, ochunk) in input.chunks_mut(block_size).zip(output.chunks_mut(block_size)) {
        func(blowfish, ichunk, ochunk);
    }

    output
}

/// Rounds the given len so that it contains blocks
/// of the same size.
fn round_len(len: usize, block_size: usize) -> usize {
    let remainder = len % block_size;
    if remainder == 0 {
        len
    } else {
        len + block_size - remainder
    }
}

#[cfg(test)]
mod tests {
    use super::{encrypt, decrypt};
    use std::ffi::OsString;

    struct Test {
        key: String,
        plain_text: String,
        cipher_text: String,
    }

    fn get_test_vector() -> Vec<Test> {
        vec![
            Test {
                key: "R=U!LH$O2B#".to_owned(),
                plain_text: "è.<Ú1477631903".to_owned(),
                cipher_text: "4a6b45612b018614c92c50dc73462bbd".to_owned(),
            },
        ]
    }

    #[test]
    fn encrypt_test_vector() {
        for test in get_test_vector() {
            let cipher_text = encrypt(&test.key, &test.plain_text);
            assert_eq!(test.cipher_text, cipher_text);
        }
    }
}

