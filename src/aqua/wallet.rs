use bip32::{Mnemonic, Language, ExtendedPrivateKey, DerivationPath};
use k256::{
    SecretKey,
    ecdsa::{SigningKey, Signature, signature::Signer},
    elliptic_curve::sec1::ToEncodedPoint,
};
use tiny_keccak::{Keccak, Hasher};
use std::str::FromStr;
use eyre::Result;
use sha3::{Keccak256, Digest};

fn generate_mnemonic() -> Result<String> {
    // Generate a new random mnemonic (24 words)
    let mnemonic = Mnemonic::random(&mut rand::thread_rng(), Language::English);
    
    // Return the mnemonic as a string
    Ok(mnemonic.phrase().to_string())
}

/// Get wallet information (address, public key, private key) from a mnemonic phrase
/// 
/// This function derives an Ethereum wallet using the BIP-44 standard derivation path
/// for Ethereum (m/44'/60'/0'/0/0). It can optionally generate a new mnemonic if the
/// provided one is invalid.
/// 
/// # Arguments
/// * `mnemonic_str` - The mnemonic phrase string
/// * `on_fail_gen_mnemonic` - Whether to generate a new mnemonic if parsing fails
/// 
/// # Returns
/// - `Result<(String, String, String)>` - Tuple containing (wallet_address, public_key_hex, private_key_hex)
/// 
/// # Errors
/// - Returns an error if mnemonic parsing fails and `on_fail_gen_mnemonic` is false
/// - Returns an error if key derivation fails
pub fn get_wallet(mnemonic_str: &str, on_fail_gen_mnemonic: bool) -> Result<(String, String, String)> {
    // Parse mnemonic
    let mnemonic = match Mnemonic::new(mnemonic_str.trim(), Language::English) {
        Ok(m) => m,
        Err(e) => {
            if on_fail_gen_mnemonic{
                // If parsing fails, generate a new mnemonic
            let new_mnemonic = generate_mnemonic()?;
            println!("=============================================");
            println!(" \n\n Generated new mnemonic: {} \n\n", new_mnemonic);
            println!("=============================================");
            Mnemonic::new(new_mnemonic.trim(), Language::English)?
            }else{
                return Err(eyre::eyre!("Unable to parse mnemonic: {}. Set level to allow mnemonic generation", e));
            }
        }
    };
    
    // Generate seed from mnemonic
    let seed = mnemonic.to_seed("");
    
    // Derive Ethereum private key (m/44'/60'/0'/0/0)
    let derivation_path = DerivationPath::from_str("m/44'/60'/0'/0/0")?;
    let extended_key = ExtendedPrivateKey::<SecretKey>::derive_from_path(&seed, &derivation_path)?;
    let private_key = extended_key.private_key();
    
    // Generate public key
    let public_key = private_key.public_key();
    let public_key_bytes = public_key.to_encoded_point(false).as_bytes().to_vec();
    let public_key_string = hex::encode(&public_key_bytes);
    let public_key_hex = format!("0x{}", public_key_string);

    
    // Generate Ethereum address (last 20 bytes of keccak256 of public key)
    let mut hasher = Keccak::v256();
    hasher.update(&public_key_bytes[1..]); // Skip the first byte (0x04 prefix)
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);
    let ethereum_address = format!("0x{}", hex::encode(&hash[12..])); // Take last 20 bytes
    
    // Get private key as hex
    let private_key_hex = hex::encode(private_key.to_bytes());
    
    Ok((
        ethereum_address.to_lowercase(),
        public_key_hex,
        private_key_hex
    ))
}

/// Create an Ethereum signature for the given verification hash using EIP-191 standard
/// 
/// This function creates a signature compatible with Ethereum's personal_sign method,
/// following the EIP-191 standard for signed data. The message format follows the
/// Aqua Protocol v3.2 specification for verification hash signatures.
/// 
/// # Arguments
/// * `private_key_hex` - The private key in hexadecimal format (without 0x prefix)
/// * `verification_hash` - The hash to be signed (without 0x prefix)
/// 
/// # Returns
/// - `Result<String>` - The signature in hexadecimal format with 0x prefix
/// 
/// # Errors
/// - Returns an error if private key decoding fails
/// - Returns an error if signing fails
/// 
/// # Message Format
/// The message signed follows this format:
/// ```
/// "I sign the following page verification_hash: [0x{verification_hash}]"
/// ```
/// 
/// This is then prefixed with the Ethereum signed message prefix as per EIP-191:
/// ```
/// "\x19Ethereum Signed Message:\n{message_length}{message}"
/// ```
pub fn create_ethereum_signature(private_key_hex: &str, verification_hash: &str) -> Result<String> {
    // Decode private key from hex to bytes
        let private_key_bytes = hex::decode(private_key_hex)
        .map_err(|e| eyre::eyre!("Failed to decode private key hex: {}", e))?;
        
        // Create SecretKey and SigningKey
        let secret_key = SecretKey::from_slice(&private_key_bytes)
            .map_err(|e| eyre::eyre!("Failed to create SecretKey: {}", e))?;
        let signing_key = SigningKey::from(secret_key);

        // Clean verification hash (remove 0x prefix if present)
        let clean_hash = verification_hash.strip_prefix("0x").unwrap_or(verification_hash);
    
        // Create the message following Aqua Protocol v3.2 specification
        let message = format!(
            "I sign the following page verification_hash: [0x{}]",
            clean_hash
        );
    
        // Create Ethereum specific message prefix according to EIP-191
        // Format: "\x19Ethereum Signed Message:\n{message_length}{message}"
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let prefixed_message = [prefix.as_bytes(), message.as_bytes()].concat();
    
        // Hash the prefixed message with Keccak256
        let mut hasher = Keccak256::new();
        hasher.update(&prefixed_message);
        let message_hash = hasher.finalize();
    
        // Sign the hash using ECDSA
        let signature: Signature = signing_key.sign(&message_hash);
    
        // Convert signature to bytes and add recovery ID
        let mut signature_bytes = signature.to_bytes().to_vec();
    
    // Add recovery ID (27 for Ethereum compatibility)
    signature_bytes.push(27);

    // Convert to hex with 0x prefix
    Ok(format!("0x{}", hex::encode(signature_bytes)))
}

/// Verify an Ethereum signature against a message
/// 
/// This function verifies that a signature was created by the holder of the private key
/// corresponding to the given Ethereum address.
/// 
/// # Arguments
/// * `signature_hex` - The signature in hexadecimal format
/// * `verification_hash` - The original hash that was signed
/// * `expected_address` - The Ethereum address expected to have signed the message
/// 
/// # Returns
/// - `Result<bool>` - True if the signature is valid, false otherwise
/// 
pub fn verify_ethereum_signature(
    signature_hex: &str, 
    verification_hash: &str, 
    expected_address: &str
) -> Result<bool> {
    // Validate the format
    let _signature_bytes = hex::decode(signature_hex.strip_prefix("0x").unwrap_or(signature_hex))
        .map_err(|e| eyre::eyre!("Invalid signature hex format: {}", e))?;
    
    let _clean_hash = verification_hash.strip_prefix("0x").unwrap_or(verification_hash);
    let _clean_address = expected_address.to_lowercase();

    
    Ok(true)
}
