use hex::{FromHex, encode};
use rand_core::{OsRng, RngCore};
use std::ffi::{CString, CStr};
use std::os::raw::c_char;
use x25519_dalek::{StaticSecret, PublicKey};
use magic_crypt::{new_magic_crypt, MagicCryptTrait};

#[no_mangle]
pub extern "C" fn generate_keys() -> *mut c_char {
    let mut rng = OsRng;
    let mut secret_bytes = [0u8; 32];
    rng.fill_bytes(&mut secret_bytes);
    let private_key = StaticSecret::from(secret_bytes);
    let public_key_bytes = PublicKey::from(&private_key).to_bytes();
    let private_key_bytes = private_key.to_bytes();
    let com_string = format!("{} {}", encode(public_key_bytes), encode(private_key_bytes));
    let c_string = CString::new(com_string).expect("Failed to create CString");
    return c_string.into_raw()
}

#[no_mangle]
pub extern "C" fn generate_shared_key(pub_key_string: *const c_char, private_key_string: *const c_char) -> *mut c_char {
    let pub_key_c_str: &CStr = unsafe { CStr::from_ptr(pub_key_string) };
    let pub_key_str: &str = match pub_key_c_str.to_str(){
        Ok(pub_key_str) => pub_key_str,
        Err(_) => return  CString::new("").expect("Failed to create CString").into_raw(),
    };

    let private_key_c_str: &CStr = unsafe { CStr::from_ptr(private_key_string) };
    let private_key_str: &str = match private_key_c_str.to_str() {
        Ok(private_key) => private_key,
        Err(_) => return  CString::new("").expect("Failed to create CString").into_raw(),
    };

    let decoded = hex_string_to_u8_array(&pub_key_str).expect("Decoding failed");
    let client_public = PublicKey::from(decoded);
    let decoded_private = hex_string_to_u8_array(&private_key_str).expect("Decoding failed");
    let private_key = StaticSecret::from(decoded_private);
    let shared_key = private_key.diffie_hellman(&client_public);
    let c_string = CString::new(encode(shared_key.to_bytes())).expect("Failed to create CString");
    return c_string.into_raw()
}

#[no_mangle]
pub extern "C" fn decrypt_data(data: *const c_char, key: *const c_char) -> *mut c_char{
    let data_c_str: &CStr = unsafe { CStr::from_ptr(data) };
    let data_str: &str = data_c_str.to_str().unwrap();
    let key_c_str: &CStr = unsafe { CStr::from_ptr(key) };
    let key_str: &str = key_c_str.to_str().unwrap();
    let mc = new_magic_crypt!(key_str, 256);
    let info = mc.decrypt_base64_to_string(&data_str).unwrap();
    let c_string = CString::new(info).expect("Failed to create CString");
    return c_string.into_raw()
}

#[no_mangle]
pub extern "C" fn encrypt_data(data: *const c_char, key_string: *const c_char) -> *mut c_char{
    let data_c_str: &CStr = unsafe { CStr::from_ptr(data) };
    let data_str: &str = data_c_str.to_str().unwrap();
    let key_str: &CStr = unsafe { CStr::from_ptr(key_string) };
    let key: &str = key_str.to_str().unwrap();
    let mc = new_magic_crypt!(key, 256);
    let base64 = mc.encrypt_str_to_base64(data_str);
    let c_string = CString::new(base64).expect("Failed to create CString");
    return c_string.into_raw()
}

fn hex_string_to_u8_array(hex_str: &str) -> Result<[u8; 32], hex::FromHexError> {
    let bytes = Vec::from_hex(hex_str)?;
    if bytes.len() == 32 {
        let mut result = [0; 32];
        result.copy_from_slice(&bytes);
        Ok(result)
    } else {
        Err(hex::FromHexError::InvalidStringLength)
    }
}