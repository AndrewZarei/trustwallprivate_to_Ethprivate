use bip39::{Language, Mnemonic};
use hdpath::StandardHDPath;
use tiny_hderive::bip32::ExtendedPrivKey;
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::SecretKey;
use sha3::{Digest, Keccak256};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;
use hmac::Hmac;
use hex;

fn mnemonic_to_seed(mnemonic: &str, password: &str) -> [u8; 64] {
    let salt = format!("mnemonic{}", password);
    let mut seed = [0u8; 64];
    pbkdf2_hmac::<Hmac<Sha512>>(
        mnemonic.as_bytes(),
        salt.as_bytes(),
        2048,
        &mut seed,
    );
    seed
}

fn main() {
    let mnemonic_phrase = "plug spray repair kingdom rent ride patient brief basic exchange banner robot"; // Replace with your real mnemonic
    let password = ""; // Optional passphrase, often empty for Trust Wallet

    // 1. Validate and use mnemonic
    let mnemonic = Mnemonic::from_phrase(mnemonic_phrase, Language::English)
        .expect("Invalid mnemonic phrase");

    // 2. Derive seed using PBKDF2
    let seed = mnemonic_to_seed(mnemonic.phrase(), password);

    // 3. Use BIP44 path for Ethereum
    let path = "m/44'/60'/0'/0/0";
    let ext = ExtendedPrivKey::derive(&seed, path).expect("Failed to derive key");

    // 4. Get private key
    let sk = SigningKey::from_bytes(&ext.secret()).expect("Failed to create signing key");
    let private_key_hex = hex::encode(ext.secret());

    // 5. Derive Ethereum address from public key
    let pubkey = sk.verifying_key();
    let pubkey_encoded = pubkey.to_encoded_point(false);
    let pubkey_bytes = pubkey_encoded.as_bytes();

    let hash = Keccak256::digest(&pubkey_bytes[1..]);
    let address = &hash[12..];

    println!("Ethereum Private Key: 0x{}", private_key_hex);
    println!("Ethereum Address: 0x{}", hex::encode(address));
}


//plug spray repair kingdom rent ride patient brief basic exchange banner robot


