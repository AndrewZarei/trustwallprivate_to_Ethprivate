use std::io;
use bip39::{Mnemonic, Language};
use hex;
use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};
use ed25519_dalek::SigningKey as EdSigningKey;
use bitcoin::bip32::{Xpriv, DerivationPath};
use bitcoin::Network;
use schnorrkel::SecretKey as SrSecretKey;

#[derive(Debug)]
struct BlockchainKey {
    name: String,
    private_key: String,
    public_key: String,
    address: Option<String>,
}

fn main() -> io::Result<()> {
    // here is input mnemonic from user
    let mut mnemonic_phrase = String::new();
    println!("Enter your Trust Wallet mnemonic phrase:");
    io::stdin().read_line(&mut mnemonic_phrase)?;
    let mnemonic_phrase = mnemonic_phrase.trim();

    let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic_phrase)
        .expect("Invalid mnemonic phrase");

    let seed = mnemonic.to_seed("");

    // 2. Derive keys for Eth&Btc&.. until this commit
    let mut keys = Vec::new();

    // Ethereum (Evm bases)
    if let Ok(eth_key) = derive_secp256k1_key(&seed, "m/44'/60'/0'/0/0", "Ethereum") {
        keys.push(eth_key);
    }

    // Bitcoin
    if let Ok(btc_key) = derive_bitcoin_key(&seed, "m/44'/0'/0'/0/0") {
        keys.push(btc_key);
    }

    // Solana (Ed25519)
    if let Ok(sol_key) = derive_ed25519_key(&seed, "m/44'/501'/0'/0'", "Solana") {
        keys.push(sol_key);
    }

    // Polkadot (Sr25519)
    if let Ok(dot_key) = derive_sr25519_key(&seed, "m/44'/354'/0'/0/0", "Polkadot") {
        keys.push(dot_key);
    }

    // 3. Print all derived keys
    println!("\n--- Derived Keys ---");
    for key in keys {
        println!("\n{}:", key.name);
        println!("Private Key: {}", key.private_key);
        println!("Public Key: {}", key.public_key);
        if let Some(addr) = key.address {
            println!("Address: {}", addr);
        }
    }

    Ok(())
}

// ===== Key Derivation Functions =====

// Derive secp256k1 keys (for ETH, BTC, etc.)
fn derive_secp256k1_key(seed: &[u8], path: &str, chain_name: &str) -> io::Result<BlockchainKey> {
    let master_key = Xpriv::new_master(Network::Bitcoin, seed)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Master key failed: {:?}", e)))?;

    let derivation_path: DerivationPath = path.parse()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Path parse failed: {:?}", e)))?;

    let ext = master_key.derive_priv(&bitcoin::secp256k1::Secp256k1::new(), &derivation_path)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Derivation failed: {:?}", e)))?;

    let private_key_bytes = ext.private_key.secret_bytes();
    let private_key_hex = hex::encode(private_key_bytes);

    // Get public key
    let signing_key = SigningKey::from_bytes(&private_key_bytes.into())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Signing key failed: {:?}", e)))?;
    let verifying_key = signing_key.verifying_key();
    let public_key_hex = hex::encode(verifying_key.to_sec1_bytes());

    // Ethereum address calculation
    let address = if chain_name == "Ethereum" {
        let uncompressed_pubkey = verifying_key.to_encoded_point(false);
        let pubkey_bytes = uncompressed_pubkey.as_bytes();
        let hash = Keccak256::digest(&pubkey_bytes[1..]);
        Some(format!("0x{}", hex::encode(&hash[12..])))
    } else {
        None
    };

    Ok(BlockchainKey {
        name: chain_name.to_string(),
        private_key: format!("0x{}", private_key_hex),
        public_key: format!("0x{}", public_key_hex),
        address,
    })
}

/// Derive Bitcoin keys
fn derive_bitcoin_key(seed: &[u8], path: &str) -> io::Result<BlockchainKey> {
    let master_key = Xpriv::new_master(Network::Bitcoin, seed)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Master key failed: {:?}", e)))?;

    let derivation_path: DerivationPath = path.parse()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Path parse failed: {:?}", e)))?;

    let ext = master_key.derive_priv(&bitcoin::secp256k1::Secp256k1::new(), &derivation_path)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Derivation failed: {:?}", e)))?;

    let private_key_wif = ext.private_key.display_secret().to_string();
    let public_key = hex::encode(ext.private_key.public_key(&bitcoin::secp256k1::Secp256k1::new()).serialize());

    Ok(BlockchainKey {
        name: "Bitcoin".to_string(),
        private_key: private_key_wif,
        public_key: format!("0x{}", public_key),
        address: None,
    })
}

/// Derive Ed25519 keys (for Solana)
fn derive_ed25519_key(seed: &[u8], path: &str, chain_name: &str) -> io::Result<BlockchainKey> {
    let master_key = Xpriv::new_master(Network::Bitcoin, seed)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Master key failed: {:?}", e)))?;

    let derivation_path: DerivationPath = path.parse()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Path parse failed: {:?}", e)))?;

    let ext = master_key.derive_priv(&bitcoin::secp256k1::Secp256k1::new(), &derivation_path)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Derivation failed: {:?}", e)))?;

    let secret_bytes = ext.private_key.secret_bytes();
    let secret_key = EdSigningKey::from_bytes(&secret_bytes);
    let public_key = secret_key.verifying_key();

    Ok(BlockchainKey {
        name: chain_name.to_string(),
        private_key: hex::encode(secret_key.to_bytes()),
        public_key: hex::encode(public_key.to_bytes()),
        address: None,
    })
}

/// Derive Sr25519 keys (for Polkadot)
fn derive_sr25519_key(seed: &[u8], path: &str, chain_name: &str) -> io::Result<BlockchainKey> {
    let master_key = Xpriv::new_master(Network::Bitcoin, seed)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Master key failed: {:?}", e)))?;

    let derivation_path: DerivationPath = path.parse()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Path parse failed: {:?}", e)))?;

    let ext = master_key.derive_priv(&bitcoin::secp256k1::Secp256k1::new(), &derivation_path)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Derivation failed: {:?}", e)))?;

    let secret_key = SrSecretKey::from_bytes(&ext.private_key.secret_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Sr25519 key conversion failed"))?;
    let public_key = secret_key.to_public();

    Ok(BlockchainKey {
        name: chain_name.to_string(),
        private_key: hex::encode(secret_key.to_bytes()),
        public_key: hex::encode(public_key.to_bytes()),
        address: None,
    })
}
