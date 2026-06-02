# hardware-keys

Native bindings for hardware key backends used by: YubiKey PIV, macOS Secure Enclave, and Windows TPM 2.0. Built with [napi-rs](https://napi.rs/) and shipped as prebuilt binaries for macOS (Apple Silicon + Intel), Linux x86_64, and Windows x86_64.

## Install

```bash
npm install hardware-keys
```

The right prebuilt binary for your platform is selected automatically. If no prebuilt is available, key operations on hardware backends will be unavailable but the package will still load.

## Supported Backends

| Backend | Algorithm | Platform | Notes |
|---------|-----------|----------|-------|
| `yubikey-piv` | ES256, RS256 | macOS, Linux, Windows | Uses slot 9e (no PIN required) |
| `secure-enclave` | ES256 | macOS (Apple Silicon) | Keys never leave the Secure Enclave |
| `windows-tpm` | ES256 | Windows | Keys generated inside TPM 2.0 via CNG, never leave hardware |

## API

```ts
import { discover, generateKey, signHash, listKeys, deleteKey } from 'hardware-keys'

// Discover available hardware backends
const backends = discover()
// [{ backend: 'yubikey-piv', description: '...', algorithms: ['ES256'], deviceId: '9570775' }]

// Generate a key on a backend
//
// YubiKey: label, permanent, requireBiometric, replaceIfExists are ignored (slot 9e is fixed)
const key = generateKey('yubikey-piv', 'ES256')

// Secure Enclave: label is required; other params default to false
const key = generateKey('secure-enclave', 'ES256', 'com.myapp.signing-key')
const key = generateKey('secure-enclave', 'ES256', 'com.myapp.signing-key', true)               // persist to keychain
const key = generateKey('secure-enclave', 'ES256', 'com.myapp.signing-key', true, false)        // no biometric
const key = generateKey('secure-enclave', 'ES256', 'com.myapp.signing-key', true, true)         // require Touch ID on every sign
const key = generateKey('secure-enclave', 'ES256', 'com.myapp.signing-key', true, false, true)  // replace if exists
// Note: if label already exists in keychain and replaceIfExists = false,
// the existing key is loaded into the in-process cache and returned as-is (get-or-create).

// Windows TPM: label and requireBiometric are supported; permanent is always true (CNG always persists)
const key = generateKey('windows-tpm', 'ES256', 'signing-key')               // no Windows Hello
const key = generateKey('windows-tpm', 'ES256', 'signing-key', false, true)  // require Windows Hello on every sign
const key = generateKey('windows-tpm', 'ES256', 'signing-key', false, false, true) // replace if exists
// { backend, keyId, algorithm, publicJwk }

// Sign a SHA-256 hash with an existing key
const result = await signHash('yubikey-piv', '9e', hashBuffer)
const result = await signHash('secure-enclave', 'com.myapp.signing-key', hashBuffer)
const result = await signHash('windows-tpm', 'signing-key', hashBuffer)
// { signature: Buffer, algorithm: 'ES256' }
// Note: signature is always raw P1363 format (r || s, 64 bytes) for ES256

// List existing keys on a backend
const keys = listKeys('yubikey-piv')
const keys = listKeys('windows-tpm')

// Secure Enclave: optional label prefix filter
const keys = listKeys('secure-enclave')                      // all keys
const keys = listKeys('secure-enclave', 'com.myapp.')        // filtered by prefix
// [{ backend, keyId, algorithm, publicJwk }]

// Delete a key by label
deleteKey('secure-enclave', 'com.myapp.signing-key')
deleteKey('windows-tpm', 'signing-key')
// YubiKey: no-op (PIV slots cannot be deleted, only overwritten via generateKey)
deleteKey('yubikey-piv', '9e')
```

### `generateKey` parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `backend` | `string` | ✓ | — | `"yubikey-piv"`, `"secure-enclave"`, or `"windows-tpm"` |
| `algorithm` | `string` | ✓ | — | `"ES256"` or `"RS256"` (YubiKey only) |
| `label` | `string` | SE / TPM | — | Key label used for lookup and deletion. For TPM, stored as `hwkey-<label>` in CNG |
| `permanent` | `boolean` | — | `false` | Persist key to keychain (Secure Enclave only). Requires binary codesigned with `keychain-access-groups` entitlement. Ignored for TPM (CNG always persists) |
| `requireBiometric` | `boolean` | — | `false` | Secure Enclave: require Touch ID / Face ID on every signing operation (`kSecAccessControlBiometryAny`). Windows TPM: require Windows Hello via `UserConsentVerifier` before every signing operation. When `false`, the key is usable programmatically with no user interaction |
| `replaceIfExists` | `boolean` | — | `false` | Delete existing key with the same label before creating. If `false` and label exists, the existing key is loaded and returned (get-or-create) |

---

## Backend notes

### Secure Enclave (macOS)

By default (`permanent: false`) a Secure Enclave key lives only for the lifetime of the current process — it is not written to the keychain. This works with any binary including unsigned `node`. Set `permanent: true` only when the binary is codesigned with the `keychain-access-groups` entitlement; otherwise the Security framework returns `errSecMissingEntitlement (-34018)`.

#### Why Secure Enclave keys are not visible outside your app

Secure Enclave keys are stored in the **Local Items** keychain (`com.apple.keybagd`), which is separate from the Login keychain shown in Keychain Access.app. This is by design — Apple's security model ensures that keychain items are only accessible to the app (or group of apps) that created them.

Per Apple's documentation on [Sharing access to keychain items among a collection of apps](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps#Establish-your-apps-private-access-group):

> Each app has access to its own private keychain access group, which no other app can access. The access group is automatically created using your Team ID and bundle ID.

And from [Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave):

> The Secure Enclave is a dedicated secure subsystem. It is isolated from the main processor to provide an extra layer of security. The key material itself is never exposed to the application processor — even when the app uses the key to perform cryptographic operations.

This means:
- Keychain Access.app **cannot display** Secure Enclave keys because it runs in a different access group.
- No other app, tool, or user process can read or export the private key material.
- The only way to verify a key exists is to query it programmatically **from within your own app**, using `listKeys()` or by calling `generateKey()` (which performs a get-or-create).

#### Enabling keychain persistence (macOS app / Electron)

**1. Create an entitlements file** (`entitlements.mac.plist`):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>keychain-access-groups</key>
    <array>
        <!--
          Format: <TeamID>.<bundle-id>
          - Replace ABCDE12345 with your Team ID (developer.apple.com/account → Membership)
          - Use your app's own bundle ID as the group name — no portal registration needed.
            Only use a custom group name if sharing keys across multiple apps,
            in which case you must register it at developer.apple.com → App Groups.
        -->
        <string>ABCDE12345.com.myapp</string>
    </array>
    <key>com.apple.application-identifier</key>
    <string>ABCDE12345.com.myapp</string>
</dict>
</plist>
```

To find your Team ID:

```bash
security find-identity -v -p codesigning | head -5
# "Developer ID Application: Your Name (ABCDE12345)"
#                                        ^^^^^^^^^^^ Team ID
```

**2. Codesign the binary** (or the Electron app bundle) with the entitlements:

```bash
# Sign a standalone binary
codesign \
  --sign "Developer ID Application: Your Name (ABCDE12345)" \
  --entitlements entitlements.mac.plist \
  --force \
  /path/to/your-binary

# Sign an Electron app bundle
codesign \
  --sign "Developer ID Application: Your Name (ABCDE12345)" \
  --entitlements entitlements.mac.plist \
  --deep --force \
  /path/to/YourApp.app
```

**3. Verify the entitlement was applied:**

```bash
codesign -d --entitlements :- /path/to/your-binary | grep -A2 keychain-access-groups
```

**4. Use `permanent: true` in your code:**

```ts
const key = generateKey(
  'secure-enclave',
  'ES256',
  'com.myapp.signing-key',
  true,   // permanent — persisted to keychain across restarts
  false,  // requireBiometric — no Touch ID prompt (programmatic access)
  false,  // replaceIfExists — load existing key if already in keychain (get-or-create)
)

// On next process start, the key is still available:
const keys = listKeys('secure-enclave', 'com.myapp.')
```

> **Electron note:** In `electron-builder`, pass the entitlements via `mac.entitlements` in `electron-builder.yml`:
> ```yaml
> mac:
>   entitlements: entitlements.mac.plist
>   entitlementsInherit: entitlements.mac.plist
>   hardenedRuntime: true
> ```

---

### Windows TPM (`windows-tpm`)

Keys are created inside the TPM via the **Microsoft Platform Crypto Provider** (CNG/NCrypt) and never leave the hardware. CNG always persists keys by name — there are no private key files on disk. The `permanent` parameter is ignored for this backend.

Key naming in CNG: `hwkey-<label>` (e.g. `hwkey-signing-key`).

When `requireBiometric: true`, Windows Hello is prompted via `Windows.Security.Credentials.UI.UserConsentVerifier` before every signing operation. `signHash` will **fail** if Windows Hello is not configured on the device, rather than silently creating a key that cannot be used.

```ts
// Basic usage — no Windows Hello
const key = generateKey('windows-tpm', 'ES256', 'signing-key')

// Require Windows Hello on every sign
const key = generateKey('windows-tpm', 'ES256', 'signing-key', false, true)

// List all TPM keys
const keys = listKeys('windows-tpm')

// Sign
const hash = crypto.createHash('sha256').update(payload).digest()
const { signature } = await signHash('windows-tpm', 'signing-key', hash)

// Delete
deleteKey('windows-tpm', 'signing-key')
```

#### Verifying a key exists outside your app

Unlike macOS, Windows CNG keys stored in the TPM Platform Crypto Provider can be inspected externally using PowerShell or `certutil`.

**certutil (Command Prompt):**
```cmd
certutil -csp "Microsoft Platform Crypto Provider" -key -user
```

If the key exists, you will see its name (e.g. `hwkey-signing-key`) in the output under the Microsoft Platform Crypto Provider section. If it is absent, the key has not been created or has been deleted.

---

## Verifying signatures on the backend service (server-side)

All backends return a raw **P1363 signature** (r ‖ s, 64 bytes) for ES256. Most server-side crypto libraries (Node.js, OpenSSL) expect DER-encoded signatures, so a conversion step is required.

### Utility (save as `hardware-key.verify.ts`)

```ts
import { createVerify, createPublicKey, KeyObject } from 'crypto'

export interface EcPublicJwk {
  kty: 'EC'; crv: 'P-256'; x: string; y: string; alg: 'ES256'; use: 'sig'
}

/**
 * Verify an ES256 signature produced by any hardware backend.
 * Pass the original payload — SHA-256 hashing is done internally.
 */
export function verifyHardwareSignature(
  publicJwk: string | EcPublicJwk,
  payload: Buffer | string,
  signature: Buffer,         // 64-byte P1363 (r || s) from SignatureResult.signature
): boolean {
  const jwk = typeof publicJwk === 'string' ? JSON.parse(publicJwk) : publicJwk
  const publicKey = createPublicKey({ key: jwk, format: 'jwk' })
  const derSig = p1363ToDer(signature)
  const verify = createVerify('SHA256')
  verify.update(typeof payload === 'string' ? Buffer.from(payload) : payload)
  return verify.verify({ key: publicKey, dsaEncoding: 'der' }, derSig)
}

/**
 * Verify when the client sends a pre-computed SHA-256 hash.
 * Use this when signHash() was called with a hash (the normal flow).
 */
export function verifyHardwareSignatureFromHash(
  publicJwk: string | EcPublicJwk,
  hash: Buffer,              // 32-byte SHA-256 hash passed to signHash()
  signature: Buffer,         // 64-byte P1363 from SignatureResult.signature
): boolean {
  const jwk = typeof publicJwk === 'string' ? JSON.parse(publicJwk) : publicJwk
  const publicKey = createPublicKey({ key: jwk, format: 'jwk' })
  const derSig = p1363ToDer(signature)
  const verify = createVerify('SHA256')
  verify.update(hash)
  return verify.verify({ key: publicKey, dsaEncoding: 'der' }, derSig)
}

/** Convert P1363 (r || s, 64 bytes) → DER SEQUENCE { INTEGER r, INTEGER s } */
function p1363ToDer(p1363: Buffer): Buffer {
  const encodeInt = (n: Buffer): Buffer => {
    let start = 0
    while (start < n.length - 1 && n[start] === 0) start++
    const trimmed = n.subarray(start)
    const needsPad = (trimmed[0] & 0x80) !== 0
    const out = Buffer.allocUnsafe(needsPad ? trimmed.length + 1 : trimmed.length)
    if (needsPad) { out[0] = 0x00; trimmed.copy(out, 1) } else { trimmed.copy(out) }
    return out
  }
  const r = encodeInt(p1363.subarray(0, 32))
  const s = encodeInt(p1363.subarray(32, 64))
  const seqLen = 2 + r.length + 2 + s.length
  const der = Buffer.allocUnsafe(2 + seqLen)
  let i = 0
  der[i++] = 0x30; der[i++] = seqLen
  der[i++] = 0x02; der[i++] = r.length; r.copy(der, i); i += r.length
  der[i++] = 0x02; der[i++] = s.length; s.copy(der, i)
  return der
}
```

### Backend service (server-side) example

```ts
import { Injectable, UnauthorizedException } from '@nestjs/common'
import { createHash } from 'crypto'
import { verifyHardwareSignature, verifyHardwareSignatureFromHash } from './hardware-key.verify'

@Injectable()
export class AuthService {
  /**
   * Verify a payload signed directly by the hardware key.
   * Works for all backends (secure-enclave, windows-tpm, yubikey-piv).
   */
  async verifyPayload(
    publicJwk: string,
    payload: Buffer,
    signature: Buffer,
  ): Promise<void> {
    if (!verifyHardwareSignature(publicJwk, payload, signature))
      throw new UnauthorizedException('Invalid hardware signature')
  }

  /**
   * Challenge-response flow — recommended for authentication.
   *
   * 1. BE issues a random challenge and stores it (Redis / DB) tied to the session
   * 2. Client computes: hash = sha256(challenge), then calls signHash(backend, label, hash)
   * 3. Client sends: { challenge, signature, publicJwk }
   * 4. BE verifies below
   */
  async verifyChallengeResponse(
    storedPublicJwk: string,  // from your user/device DB
    challenge: string,         // the challenge BE issued
    signature: Buffer,         // SignatureResult.signature from client
  ): Promise<void> {
    const hash = createHash('sha256').update(challenge).digest()
    if (!verifyHardwareSignatureFromHash(storedPublicJwk, hash, signature))
      throw new UnauthorizedException('Challenge signature invalid')
  }
}
```

> **Security note:** Always store the `publicJwk` server-side and look it up by device/user identity — never trust a `publicJwk` sent by the client at verification time.

---

## License

MIT
