use argon2::{
    Algorithm, Argon2, Params, Version as Argon2Version,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::Error;

#[derive(Deserialize)]
struct HashOptions {
    salt: Bytes,
    secret: Option<Bytes>,
    data: Option<Bytes>,
    version: Option<String>,
    variant: Option<String>,
    #[serde(rename(deserialize = "memoryCost"))]
    memory_cost: Option<u32>,
    #[serde(rename(deserialize = "timeCost"))]
    time_cost: Option<u32>,
    #[serde(rename(deserialize = "lanes"))]
    lanes: Option<u32>,
    #[serde(rename(deserialize = "hashLength"))]
    hash_length: Option<u32>,
}

#[derive(Deserialize)]
struct HashParams {
    password: String,
    options: HashOptions,
}

#[derive(Serialize)]
struct HashResult {
    result: Vec<u8>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct VerifyParams {
    password: String,
    hash: String,
    secret: Option<Bytes>,
    data: Option<Bytes>,
}

#[derive(Serialize)]
struct VerifyResult {
    result: bool,
    error: Option<String>,
}

fn pack_into_buf(s: &str) -> *const u8 {
    let len = (s.len() as u32).to_be_bytes();
    let mut buf = len.to_vec();
    buf.extend_from_slice(s.as_bytes());

    let buf = buf.into_boxed_slice();
    let buf_ptr = buf.as_ptr();

    std::mem::forget(buf);
    buf_ptr
}

#[no_mangle]
pub extern "C" fn free_buf(ptr: *mut u8, len: usize) {
    drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)) });
}

#[no_mangle]
pub extern "C" fn hash(ptr: *const u8, len: usize) -> *const u8 {
    let params_buf = unsafe { std::slice::from_raw_parts(ptr, len) };

    let result = match hash_internal(params_buf) {
        Ok(result) => HashResult {
            result: result.into_bytes(),
            error: None,
        },
        Err(err) => HashResult {
            result: vec![],
            error: Some(format!("{err}")),
        },
    };

    let result = serde_json::to_string(&result).expect("failed to json-strigify the result");

    pack_into_buf(&result)
}

#[no_mangle]
pub extern "C" fn verify(ptr: *const u8, len: usize) -> *const u8 {
    let params_buf = unsafe { std::slice::from_raw_parts(ptr, len) };

    let result = match verify_internal(params_buf) {
        Ok(result) => VerifyResult {
            result,
            error: None,
        },
        Err(err) => VerifyResult {
            result: false,
            error: Some(format!("{err}")),
        },
    };

    let result = serde_json::to_string(&result).expect("failed to json-strigify the result");

    pack_into_buf(&result)
}

fn hash_internal(params_buf: &[u8]) -> Result<String, Error> {
    let params: HashParams = serde_json::from_slice(params_buf)?;

    // Parse algorithm variant
    let algorithm = match params.options.variant.as_deref() {
        Some("argon2d") => Algorithm::Argon2d,
        Some("argon2i") => Algorithm::Argon2i,
        Some("argon2id") | Some(_) | None => Algorithm::Argon2id,
    };

    // Parse version
    let version = match params.options.version.as_deref() {
        Some("16") => Argon2Version::V0x10,
        Some("19") | Some(_) | None => Argon2Version::V0x13,
    };

    // Create parameters
    let argon2_params = Params::new(
        params.options.memory_cost.unwrap_or(4096),
        params.options.time_cost.unwrap_or(3),
        params.options.lanes.unwrap_or(1),
        params.options.hash_length.map(|h| h as usize),
    )
    .map_err(Error::Argon2)?;

    // Create Argon2 instance
    let argon2 = if let Some(ref secret) = params.options.secret {
        Argon2::new_with_secret(secret, algorithm, version, argon2_params).map_err(Error::Argon2)?
    } else {
        Argon2::new(algorithm, version, argon2_params)
    };

    // `hash_password_with_salt` takes raw salt bytes
    // (it encodes to B64 internally), so no manual base64 step is needed.
    let salt_bytes: &[u8] = &params.options.salt;

    // Hash password
    let password_to_hash = if let Some(ref data) = params.options.data {
        // Concatenate password with additional data
        let mut combined = params.password.as_bytes().to_vec();
        combined.extend_from_slice(data);
        combined
    } else {
        params.password.as_bytes().to_vec()
    };

    let password_hash = argon2
        .hash_password_with_salt(&password_to_hash, salt_bytes)
        .map_err(|_| Error::Argon2(argon2::Error::OutputTooShort))?;

    Ok(password_hash.to_string())
}

fn verify_internal(params_buf: &[u8]) -> Result<bool, Error> {
    let options: VerifyParams = serde_json::from_slice(params_buf)?;

    // Parse the hash string
    let parsed_hash = PasswordHash::new(&options.hash)
        .map_err(|_| Error::Argon2(argon2::Error::OutputTooShort))?;

    // Get algorithm from the hash
    let algorithm_str = parsed_hash.algorithm.as_str();
    let algorithm = match algorithm_str {
        "argon2d" => Algorithm::Argon2d,
        "argon2i" => Algorithm::Argon2i,
        _ => Algorithm::Argon2id,
    };

    let version = Argon2Version::V0x13; // Default version

    // Extract parameters from hash
    let params_map = &parsed_hash.params;
    let memory_cost = params_map
        .get("m")
        .and_then(|p| p.decimal().ok())
        .unwrap_or(4096) as u32;
    let time_cost = params_map
        .get("t")
        .and_then(|p| p.decimal().ok())
        .unwrap_or(3) as u32;
    let lanes = params_map
        .get("p")
        .and_then(|p| p.decimal().ok())
        .unwrap_or(1) as u32;

    let argon2_params = Params::new(memory_cost, time_cost, lanes, None).map_err(Error::Argon2)?;

    // Create Argon2 instance
    let argon2 = if let Some(ref secret) = options.secret {
        Argon2::new_with_secret(secret, algorithm, version, argon2_params).map_err(Error::Argon2)?
    } else {
        Argon2::new(algorithm, version, argon2_params)
    };

    // Verify password
    let password_to_verify = if let Some(ref data) = options.data {
        // Concatenate password with additional data
        let mut combined = options.password.as_bytes().to_vec();
        combined.extend_from_slice(data);
        combined
    } else {
        options.password.as_bytes().to_vec()
    };

    let result = argon2
        .verify_password(&password_to_verify, &parsed_hash)
        .is_ok();

    Ok(result)
}
