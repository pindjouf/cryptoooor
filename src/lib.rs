use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce, Key
};
use typenum;
use rprompt;
use std::fs;
use scrypt::{
    password_hash::{
        rand_core::OsRng,
        PasswordHasher, SaltString
    },
    Scrypt,
    Params
};

pub fn encrypt(content: Vec<u8>, key: &Key<Aes256Gcm>) -> Result<(Vec<u8>, Nonce<typenum::U12>), Box<dyn std::error::Error>> {
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher.encrypt(&nonce, &*content.as_ref()).map_err(|e| format!("Encryption failed: {}", e))?;

    Ok((ciphertext, nonce))
}

pub fn decrypt(encrypted_content: Vec<u8>, key: &Key<Aes256Gcm>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let (ciphertext, nonce_vec): (Vec<u8>, Vec<u8>) = bincode::deserialize(&encrypted_content)?;
    let nonce = Nonce::from_slice(&nonce_vec);
    let cipher = Aes256Gcm::new(key);

    let decrypted_content = cipher.decrypt(nonce, &*ciphertext.as_ref()).map_err(|e| format!("Decryption failed: {}", e))?;


    Ok(decrypted_content)
}

pub fn derive_key(hash: Vec<u8>, salt: Vec<u8>) -> Result<Key<Aes256Gcm>, Box<dyn std::error::Error>> {
    let params: Params = Params::new(15, 8, 1, 32)?;

    let hash_str = String::from_utf8(hash)?;
    let salt_str = String::from_utf8(salt)?;

    let mut key_bytes = vec![0u8; 32];
    
    scrypt::scrypt(
        hash_str.as_bytes(),
        salt_str.as_bytes(),
        &params,
        &mut key_bytes
    )?;

    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);

    Ok(*key)
}

pub fn generate_hash_and_salt() -> Result<(), Box<dyn std::error::Error>> {
    let binding = rprompt::prompt_reply("Enter a password to be hashed: ").unwrap();
    let password = binding.as_bytes();
    let salt = SaltString::generate(&mut OsRng);

    let password_hash = Scrypt.hash_password(password, &salt)?;

    fs::write("hash.txt", password_hash.to_string())?;
    fs::write("salt.txt", salt.to_string())?;

    Ok(())
}
