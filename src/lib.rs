use napi::bindgen_prelude::*;
use napi_derive::napi;

mod yubikey_piv;

#[cfg(target_os = "macos")]
mod secure_enclave;

#[cfg(target_os = "windows")]
mod windows_tpm;

/// Discovered hardware key backend
#[napi(object)]
pub struct HardwareKeyInfo {
    /// "yubikey-piv" or "secure-enclave"
    pub backend: String,
    /// Human-readable description
    pub description: String,
    /// Supported algorithms: "ES256", "RS256", etc.
    pub algorithms: Vec<String>,
    /// For YubiKey: serial number. For Secure Enclave: "local"
    pub device_id: String,
}

/// Result of key generation
#[napi(object)]
pub struct GeneratedKey {
    /// Backend that holds the key
    pub backend: String,
    /// Key identifier (slot for PIV, tag for Secure Enclave)
    pub key_id: String,
    /// Algorithm used
    pub algorithm: String,
    /// Public key as JWK JSON string
    pub public_jwk: String,
}

/// Result of a signing operation
#[napi(object)]
pub struct SignatureResult {
    /// Raw signature bytes (r||s for ECDSA, raw for RSA)
    pub signature: Buffer,
    /// Algorithm used
    pub algorithm: String,
}

/// Discover available hardware key backends
#[napi]
pub fn discover() -> Vec<HardwareKeyInfo> {
    let mut backends = Vec::new();

    if let Some(info) = yubikey_piv::discover() {
        backends.push(info);
    }

    #[cfg(target_os = "macos")]
    if let Some(info) = secure_enclave::discover() {
        backends.push(info);
    }

    #[cfg(target_os = "windows")]
    if let Some(info) = windows_tpm::discover() {
        backends.push(info);
    }

    backends
}

/// Generate a key on the specified backend.
///
/// # Parameters (Secure Enclave only)
/// - `label`              – Key label stored as `kSecAttrApplicationLabel`. Required for
///                          Secure Enclave; ignored for YubiKey (slot is fixed to 9e).
/// - `permanent`          – Persist to keychain (`kSecAttrIsPermanent`). Requires the
///                          binary to be codesigned with `keychain-access-groups`.
///                          Ignored for YubiKey.
/// - `require_biometric`  – When `true`, Touch ID / Face ID is prompted on every signing
///                          operation (`kSecAccessControlBiometryAny`). When `false`,
///                          the key is usable programmatically with no user interaction.
///                          Ignored for YubiKey.
/// - `replace_if_exists`  – When `true` and `label` already exists, the old key is
///                          deleted before creating a new one. When `false` and the key
///                          already exists in the keychain it is loaded into the
///                          in-process cache and returned as-is. Ignored for YubiKey.
#[napi]
#[allow(unused_variables)]
pub fn generate_key(
    backend: String,
    algorithm: String,
    label: Option<String>,
    permanent: Option<bool>,
    require_biometric: Option<bool>,
    replace_if_exists: Option<bool>,
) -> Result<GeneratedKey> {
    match backend.as_str() {
        "yubikey-piv" => yubikey_piv::generate_key(&algorithm),

        #[cfg(target_os = "macos")]
        "secure-enclave" => {
            let label = label.ok_or_else(|| {
                Error::from_reason("'label' is required for the secure-enclave backend")
            })?;
            let permanent = permanent.unwrap_or(false);
            let require_biometric = require_biometric.unwrap_or(false);
            let policy = if replace_if_exists.unwrap_or(false) {
                secure_enclave::DuplicateLabelPolicy::Replace
            } else {
                secure_enclave::DuplicateLabelPolicy::Error
            };
            secure_enclave::generate_key(&label, &algorithm, permanent, require_biometric, policy)
        }

        #[cfg(target_os = "windows")]
        "windows-tpm" => {
            let label = label.ok_or_else(|| {
                Error::from_reason("'label' is required for the windows-tpm backend")
            })?;
            let require_biometric = require_biometric.unwrap_or(false);
            let policy = if replace_if_exists.unwrap_or(false) {
                windows_tpm::DuplicateLabelPolicy::Replace
            } else {
                windows_tpm::DuplicateLabelPolicy::Error
            };
            windows_tpm::generate_key(&label, &algorithm, require_biometric, policy)
        }

        _ => Err(Error::from_reason(format!("Unknown backend: {}", backend))),
    }
}

/// Sign a hash with a hardware key.
/// For JWT: pass the SHA-256 hash of the `header.payload` string.
#[napi]
pub async fn sign_hash(backend: String, key_id: String, hash: Buffer) -> Result<SignatureResult> {
    match backend.as_str() {
        "yubikey-piv" => yubikey_piv::sign_hash(&key_id, &hash),
        #[cfg(target_os = "macos")]
        "secure-enclave" => secure_enclave::sign_hash(&key_id, &hash),
        #[cfg(target_os = "windows")]
        "windows-tpm" => windows_tpm::sign_hash(&key_id, &hash).await,
        _ => Err(Error::from_reason(format!("Unknown backend: {}", backend))),
    }
}

/// List existing keys on a backend.
///
/// - `prefix` – Optional label prefix filter (Secure Enclave only; ignored for YubiKey).
#[napi]
pub fn list_keys(backend: String, prefix: Option<String>) -> Result<Vec<GeneratedKey>> {
    match backend.as_str() {
        "yubikey-piv" => yubikey_piv::list_keys(),
        #[cfg(target_os = "macos")]
        "secure-enclave" => secure_enclave::list_keys(prefix.as_deref()),
        #[cfg(target_os = "windows")]
        "windows-tpm" => {
            // prefix filter is not supported for windows-tpm — CNG does not provide
            // a prefix query API; all hwkey- keys are returned and filtered here if needed
            let keys = windows_tpm::list_keys()?;
            if let Some(p) = prefix.as_deref() {
                Ok(keys.into_iter().filter(|k| k.key_id.starts_with(p)).collect())
            } else {
                Ok(keys)
            }
        }
        _ => Err(Error::from_reason(format!("Unknown backend: {}", backend))),
    }
}

/// Delete a key by label.
///
/// For Secure Enclave: removes from the in-process cache and keychain (if permanent).
/// For YubiKey: no-op — PIV slots cannot be deleted, only overwritten via `generate_key`.
#[napi]
pub fn delete_key(backend: String, label: String) -> Result<()> {
    match backend.as_str() {
        "yubikey-piv" => yubikey_piv::delete_key(&label),
        #[cfg(target_os = "macos")]
        "secure-enclave" => secure_enclave::delete_key(&label),
        #[cfg(target_os = "windows")]
        "windows-tpm" => windows_tpm::delete_key(&label),
        _ => Err(Error::from_reason(format!("Unknown backend: {}", backend))),
    }
}
