mod utils;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm,
};
use clap::{Parser, Subcommand};
use rand::RngCore;
use rpassword::prompt_password;
use rsa::rand_core::OsRng;
use rsa::BigUint;
use rsa::{traits::PublicKeyParts, Pkcs1v15Encrypt, RsaPublicKey};
use std::fs;
use std::io::{self};
use std::{
    fs::File,
    io::{Read, Write},
};
use utils::{
    derive_aes_key_from_x, derive_aes_key, display_public_key, pkcs1v15_encrypt_unpad,
    validate_file_path,
};
use yubikey::{
    piv::{AlgorithmId, SlotId},
    Key, YubiKey,
};
use yubikey::{PinPolicy, TouchPolicy};

/// Interacts with a YubiKey for RSA encryption and decryption operations
#[derive(Parser)]
#[clap(
    author = "Alien Coder",
    version = "0.1.0",
    about = "YubiKey CLI for RSA-KEM using AES-GCM for encryption and decryption operations.\n
Uses the RSA keys stored in Key Management slot 9d.\n
Defaults to 2048 bit RSA keys."
)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypts a file using YubiKey's RSA public key
    Encrypt {
        #[clap(short, long, value_name = "FILE")]
        input: String,
        #[clap(short, long, value_name = "FILE")]
        output: String,
    },
    /// Decrypts a file using YubiKey's RSA private key
    Decrypt {
        #[clap(short, long, value_name = "FILE")]
        input: String,
        #[clap(short, long, value_name = "FILE")]
        output: String,
        #[clap(
            long,
            default_value = "2048",
            help = "Specify RSA key length (1024 or 2048)"
        )]
        length: String,
    },
    /// Extracts the RSA public key from YubiKey
    ExtractKey,

    /// Generates an RSA key in the key management slot
    GenerateKey {
        #[clap(
            long,
            default_value = "2048",
            help = "Specify RSA key length (1024 or 2048 bits)"
        )]
        length: String,
    },
}

#[derive(Clone, Copy)]
pub enum RsaKeyLength {
    Rsa1024,
    Rsa2048,
}

impl RsaKeyLength {
    fn to_algorithm_id(&self) -> AlgorithmId {
        match self {
            RsaKeyLength::Rsa1024 => AlgorithmId::Rsa1024,
            RsaKeyLength::Rsa2048 => AlgorithmId::Rsa2048,
        }
    }
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Encrypt { input, output } => {
            validate_file_path(input, true).expect("Invalid input file path");
            validate_file_path(output, false).expect("Invalid output file path");
            let pin = prompt_password("Enter PIN: ").expect("Failed to prompt for PIN");
            encrypt_file(input, output, &pin).expect("Encryption failed");
        }
        Commands::Decrypt {
            length,
            input,
            output,
        } => {
            validate_file_path(input, true).expect("Invalid input file path");
            validate_file_path(output, false).expect("Invalid output file path");
            let key_length = match length.as_str() {
                "1024" => RsaKeyLength::Rsa1024,
                _ => RsaKeyLength::Rsa2048,
            };
            let pin = prompt_password("Enter PIN: ").expect("Failed to prompt for PIN");
            decrypt_file(input, output, &pin, key_length).expect("Decryption failed");
        }
        Commands::ExtractKey => {
            let pin: String = prompt_password("Enter PIN: ").expect("Failed to prompt for PIN");
            extract_rsa_public_key(&pin).expect("Failed to extract RSA public key");
        }
        Commands::GenerateKey { length } => {
            let key_length = match length.as_str() {
                "1024" => RsaKeyLength::Rsa1024,
                _ => RsaKeyLength::Rsa2048,
            };
            let pin = prompt_password("Enter PIN: ").expect("Failed to prompt for PIN");
            generate_rsa_key(&pin, key_length).expect("Failed to generate RSA key");
        }
    }
}

fn encrypt_file(input: &str, output: &str, pin: &str) -> Result<(), io::Error> {
    let mut yubikey: YubiKey =
        YubiKey::open().map_err(|e| io::Error::new(io::ErrorKind::NotFound, e))?;

    yubikey
        .verify_pin(pin.as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;

    // Retrieve RSA public key from YubiKey
    let rsa_public_key = get_rsa_public_key(&mut yubikey, SlotId::KeyManagement)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Encrypt the large file using RSA-KEM
    rsa_kem_bundle(input, &rsa_public_key, output).expect("Error encrypting file");

    Ok(())
}

fn decrypt_file(
    encrypted_file_path: &str,
    output_path: &str,
    pin: &str,
    key_length: RsaKeyLength,
) -> Result<(), io::Error> {
    // Read the encrypted file
    let mut file = File::open(encrypted_file_path)?;
    let mut encrypted_data = Vec::new();
    file.read_to_end(&mut encrypted_data)?;

    // Sizes for nonce, salt, and encrypted `x`
    let key_size_bytes = match key_length {
        RsaKeyLength::Rsa1024 => 128,
        RsaKeyLength::Rsa2048 => 256,
    };
    let nonce_size = 12;
    let salt_size = 22;

    // Calculate the start index of each component
    let encrypted_x_start = encrypted_data.len() - key_size_bytes;
    let salt_start = encrypted_x_start - salt_size;
    let nonce_start = salt_start - nonce_size;

    // Extract each element
    let (ciphertext, rest) = encrypted_data.split_at(nonce_start);
    let (nonce_bytes, rest) = rest.split_at(nonce_size);
    let (salt_bytes, encrypted_x) = rest.split_at(salt_size);

    let mut yubikey = YubiKey::open().map_err(|e| io::Error::new(io::ErrorKind::NotFound, e))?;

    yubikey
        .verify_pin(pin.as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;

    let decrypted_x = decrypt_data(
        &mut yubikey,
        encrypted_x,
        key_length.to_algorithm_id(),
        SlotId::KeyManagement,
    )
    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let rsa_public_key = get_rsa_public_key(&mut yubikey, SlotId::KeyManagement)
        .expect("Failed to get RSA public key");

    // Remove PKCS1v1.5 padding
    let decrypted_x_without_padding = pkcs1v15_encrypt_unpad(decrypted_x, rsa_public_key.size())
        .expect("Error while removing padding");

    // Derive AES key from decrypted x and salt
    let aes_key = derive_aes_key(&decrypted_x_without_padding, salt_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Error during key derivation"))?;

    // Decrypt AES-encrypted file data
    let decrypted_data = decrypt_file_aes_gcm(ciphertext, &aes_key, nonce_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Error during AES decryption"))?;

    // Write decrypted data to output file
    let mut output_file = File::create(output_path)?;
    output_file.write_all(&decrypted_data)?;

    Ok(())
}

fn extract_rsa_public_key(pin: &str) -> Result<(), io::Error> {
    let mut yubikey = YubiKey::open().map_err(|e| io::Error::new(io::ErrorKind::NotFound, e))?;

    yubikey
        .verify_pin(pin.as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;

    let rsa_public_key = get_rsa_public_key(&mut yubikey, SlotId::KeyManagement)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    display_public_key(&rsa_public_key)?;
    Ok(())
}

fn generate_rsa_key(pin: &str, key_length: RsaKeyLength) -> Result<(), io::Error> {
    let mut yubikey: YubiKey =
        YubiKey::open().map_err(|e| io::Error::new(io::ErrorKind::NotFound, e))?;

    yubikey
        .verify_pin(pin.as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;

    let algorithm = key_length.to_algorithm_id();
    let pin_policy = PinPolicy::Once;
    let touch_policy = TouchPolicy::Never;

    match yubikey::piv::generate(
        &mut yubikey,
        SlotId::KeyManagement,
        algorithm,
        pin_policy,
        touch_policy,
    ) {
        Ok(public_key_info) => {
            println!(
                "RSA Key generated successfully. Public key info: {:?}",
                public_key_info
            );
            Ok(())
        }
        Err(e) => Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to generate RSA key: {}", e),
        )),
    }
}

// Function to retrieve the RSA public key from the YubiKey
fn get_rsa_public_key(yubikey: &mut YubiKey, slot: SlotId) -> Result<RsaPublicKey, String> {
    let keys = Key::list(yubikey).map_err(|e| e.to_string())?;
    for key in keys {
        if key.slot() == slot {
            let cert = key.certificate();
            let pubkey_info = cert.subject_pki();
            let rsa_public_key = RsaPublicKey::try_from(pubkey_info)
                .map_err(|_| "Failed to convert to RsaPublicKey".to_string())?;

            return Ok(rsa_public_key);
        }
    }

    Err("RSA public key not found in the specified slot".to_string())
}

// Wrapper function to call `yubikey` crate's `decrypt_data` function
fn decrypt_data(
    yubikey: &mut YubiKey,
    encrypted_data: &[u8],
    algorithm: AlgorithmId,
    key: SlotId,
) -> Result<Vec<u8>, yubikey::Error> {
    yubikey::piv::decrypt_data(yubikey, encrypted_data, algorithm, key)
        .map(|buffer| buffer.to_vec())
}

fn generate_x(public_key: &RsaPublicKey) -> Result<BigUint, Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    // Generate a random number with one byte less than the modulus size
    // Reduce the size of x_bytes to accommodate padding by subtracting 11 bytes
    let mut x_bytes = vec![0u8; public_key.size() - 1 - 11];
    rng.fill_bytes(&mut x_bytes);

    // Ensure 'x' is not zero
    x_bytes[0] |= 0b00000001;
    // Convert to BigUint and add 2 to ensure it's in the range [2, n - 1]
    let x = BigUint::from_bytes_be(&x_bytes) + 2u8;

    // Check if x is less than n - 1
    let n_minus_1 = public_key.n() - 1u8;
    if x >= n_minus_1 {
        return Err("x is not within the range [2, n - 1]".into());
    }

    Ok(x)
}

fn encrypt_file_aes_gcm(
    file_path: &str,
    key_bytes: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    if key_bytes.len() != 32 {
        return Err("Key must be exactly 32 bytes long".into());
    }

    let data = fs::read(file_path).expect("Error reading file");

    let cipher = Aes256Gcm::new_from_slice(key_bytes).map_err(|_| "Invalid key length")?;
    let nonce = Aes256Gcm::generate_nonce(rand::thread_rng());

    let ciphertext = cipher
        .encrypt(GenericArray::from_slice(&nonce), data.as_ref())
        .map_err(|_| "Error during AES encryption")?;

    Ok((ciphertext, nonce.to_vec()))
}

fn decrypt_file_aes_gcm(
    ciphertext: &[u8],
    key_bytes: &[u8],
    nonce_bytes: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key: &GenericArray<u8, _> = GenericArray::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = GenericArray::from_slice(nonce_bytes);

    let decrypted_data = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Error during AES decryption")?;

    Ok(decrypted_data)
}

fn encrypt_x_with_rsa(
    x: &BigUint,
    public_key: &RsaPublicKey,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let x_bytes: Vec<u8> = x.to_bytes_be();

    let encrypted_data = public_key
        .encrypt(&mut OsRng, Pkcs1v15Encrypt, &x_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    Ok(encrypted_data)
}

fn rsa_kem_bundle(
    file_path: &str,
    rsa_public_key: &RsaPublicKey,
    output_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Generate `x`
    let x = generate_x(rsa_public_key)?;

    // Derive the AES key
    let (aes_key, salt_bytes) = derive_aes_key_from_x(&x).map_err(|_| "Error during key derivation")?;

    // Encrypt the file with AES-GCM
    let (ciphertext, nonce_bytes) =
        encrypt_file_aes_gcm(file_path, &aes_key).map_err(|_| "Error during encryption")?;

    // Encrypt `x` with RSA
    let encrypted_x = encrypt_x_with_rsa(&x, rsa_public_key)?;

    // Bundle the AES-encrypted data, RSA-encrypted `x`, nonce, and salt into the `output_file`
    let mut output_file = File::create(&output_path)?;
    output_file.write_all(&ciphertext)?;
    output_file.write_all(&nonce_bytes)?;
    output_file.write_all(&salt_bytes)?;
    output_file.write_all(&encrypted_x)?;

    Ok(())
}
