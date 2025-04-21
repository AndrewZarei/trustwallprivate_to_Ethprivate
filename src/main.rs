use bip39::{Mnemonic, Language};
use hdwallet::{DefaultKeyChain, KeyChain};
use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};
use hex;
use tiny_hderive::bip32::ExtendedPrivKey;

fn main() {
    let mnemonic_phrase = "rifle embrace honey will museum undo solar unlock office choose gift light"; 
    //0x6E7Bb666e4bb299ca15Dc18FAcaE7bBB9189fe42
    // // Replace with your real mnemonic
    let password = ""; // Optional passphrase, often empty for Trust Wallet

    // 1. Validate and use mnemonic
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic_phrase)
        .expect("Invalid mnemonic phrase");

    // 2. Derive seed using PBKDF2 (handled internally by to_seed())
    let seed = mnemonic.to_seed(password);

    // 3. Use BIP44 path for Ethereum
    let path = "m/44'/60'/0'/0/0";
    let ext = ExtendedPrivKey::derive(&seed, path).expect("Failed to derive key");

    // 4. Get private key
    let private_key_bytes = ext.secret();
    let private_key_hex = hex::encode(private_key_bytes);

    // 5. Derive Ethereum address from private key
    let signing_key = SigningKey::from_bytes(&private_key_bytes.into())
        .expect("Invalid private key");
    let verifying_key = signing_key.verifying_key();
    let uncompressed_pubkey = verifying_key.to_encoded_point(false);
    let pubkey_bytes = uncompressed_pubkey.as_bytes();
    
    // Ethereum address is Keccak-256 hash of the public key (without 0x04 prefix)
    let hash = Keccak256::digest(&pubkey_bytes[1..]); // Skip the first byte
    let address = &hash[12..]; // Take last 20 bytes

    println!("Ethereum Private Key: 0x{}", private_key_hex);
    println!("Ethereum Address: 0x{}", hex::encode(address));
}