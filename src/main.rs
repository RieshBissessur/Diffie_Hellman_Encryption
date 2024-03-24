use hex::{FromHex, encode};
use rand_core::{OsRng, RngCore};
use x25519_dalek::{StaticSecret, PublicKey};
use magic_crypt::{new_magic_crypt, MagicCryptTrait};

fn main() {
    let str_arr = generate_public_key();
    let mut keys = str_arr.split_whitespace();
    let key = generate_shared_key(keys.next().unwrap().to_string(), keys.next().unwrap().to_string());
    let test = encrypt_data("Test.".to_string(), key.clone());
    println!("Encrypted Data: {}",test);
    let answ = decrypt_data(test, key.clone());
    println!("Decrypted Data: {}",answ);
}

fn generate_public_key() -> String{
    let mut rng = OsRng;
    let mut secret_bytes = [0u8; 32];
    rng.fill_bytes(&mut secret_bytes);
    let private_key = StaticSecret::from(secret_bytes);
    let public_key = PublicKey::from(&private_key);
    let result =  format!("{} {}",encode(public_key.to_bytes()), encode(private_key.to_bytes()));
    return result;

}

fn generate_shared_key(pub_key: String, private_key: String) -> String {
    let decoded = hex_string_to_u8_array(&pub_key).expect("Decoding failed");
    let public_key = PublicKey::from(decoded);
    let decoded_private = hex_string_to_u8_array(&private_key).expect("Decoding failed");
    let private_key = StaticSecret::from(decoded_private);
    let shared_key = private_key.diffie_hellman(&public_key);
    encode(shared_key.to_bytes())
}

 fn decrypt_data(data: String, key: String) -> String{
    let mc = new_magic_crypt!(key, 256);
    let info = mc.decrypt_base64_to_string(&data).unwrap();
    return info;
}

fn encrypt_data(data: String, key: String) -> String{
    let mc = new_magic_crypt!(key, 256);
    let base64 = mc.encrypt_str_to_base64(data);
    return base64;
}

fn hex_string_to_u8_array(hex_str: &str) -> Result<[u8; 32], hex::FromHexError> {
    let bytes = Vec::from_hex(hex_str)?;
    if bytes.len() == 32 {
        let mut result = [0; 32];
        result.copy_from_slice(&bytes);
        Ok(result)
    } else {
        // If the length is not 32, return an error or handle the case accordingly
        Err(hex::FromHexError::InvalidStringLength)
    }
}