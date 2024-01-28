use std::{io, path::Path};

use argon2::{password_hash::SaltString, Argon2};
use rsa::{pkcs8::EncodePublicKey, rand_core::OsRng, BigUint, RsaPublicKey};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

pub fn validate_file_path(path: &str, is_input: bool) -> Result<(), io::Error> {
    let path = Path::new(path);
    if is_input {
        if !path.exists() || !path.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Input file not found",
            ));
        }
    } else {
        if let Some(parent) = path.parent() {
            if !parent.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Invalid output file path",
                ));
            }
        }
    }
    Ok(())
}

pub fn pkcs1v15_encrypt_unpad(em: Vec<u8>, k: usize) -> Result<Vec<u8>, String> {
    if k < 11 {
        return Err("Decryption error: key size is too small".to_string());
    }

    let first_byte_is_zero = em[0].ct_eq(&0u8);
    let second_byte_is_two = em[1].ct_eq(&2u8);

    let mut looking_for_index = 1u8;
    let mut index = 0u32;

    for (i, &el) in em.iter().enumerate().skip(2) {
        let equals0 = el.ct_eq(&0u8);
        index.conditional_assign(&(i as u32), Choice::from(looking_for_index) & equals0);
        looking_for_index.conditional_assign(&0u8, equals0);
    }

    let valid_ps = Choice::from((((2i32 + 8i32 - index as i32 - 1i32) >> 31) & 1) as u8);
    let valid =
        first_byte_is_zero & second_byte_is_two & Choice::from(!looking_for_index & 1) & valid_ps;

    if valid.unwrap_u8() == 0 {
        return Err("Decryption error: invalid padding".to_string());
    }

    Ok(em[(index + 1) as usize..].to_vec())
}

pub fn display_public_key(rsa_public_key: &RsaPublicKey) -> Result<(), io::Error> {
    let der_encoded = rsa_public_key
        .to_public_key_der()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let pem_encoded = der_encoded
        .to_pem("PUBLIC KEY", rsa::pkcs8::LineEnding::LF)
        .expect("Error encoding public key to PEM format");

    println!("RSA Public Key in PEM format:\n{}", pem_encoded);
    Ok(())
}

pub fn derive_aes_key_from_x(x: &BigUint) -> Result<(Vec<u8>, Vec<u8>), argon2::password_hash::Error> {
    let x_bytes = x.to_bytes_be();
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let mut password_hash = [0u8; 32];
    argon2
        .hash_password_into(
            &x_bytes,
            &salt.to_string().as_bytes().to_vec(),
            &mut password_hash,
        )
        .expect("Argon2 error");

    Ok((password_hash.to_vec(), salt.to_string().as_bytes().to_vec()))
}

pub fn derive_aes_key(x: &[u8], salt: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let argon2 = Argon2::default();
    let mut password_hash = [0u8; 32];
    argon2
        .hash_password_into(x, salt, &mut password_hash)
        .expect("Argon2 error");

    Ok(password_hash.to_vec())
}