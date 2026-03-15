# Krypton

[![npm version](https://img.shields.io/npm/v/@d1g1tal/krypton?color=blue)](https://www.npmjs.com/package/@d1g1tal/krypton)
[![npm downloads](https://img.shields.io/npm/dm/@d1g1tal/krypton)](https://www.npmjs.com/package/@d1g1tal/krypton)
[![CI](https://github.com/D1g1talEntr0py/krypton/actions/workflows/ci.yml/badge.svg)](https://github.com/D1g1talEntr0py/krypton/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/D1g1talEntr0py/krypton/graph/badge.svg)](https://codecov.io/gh/D1g1talEntr0py/krypton)
[![License: MIT](https://img.shields.io/github/license/D1g1talEntr0py/krypton)](https://github.com/D1g1talEntr0py/krypton/blob/main/LICENSE)
[![Node.js](https://img.shields.io/node/v/@d1g1tal/krypton)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-blue?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)

TypeScript Wrapper for the Web Crypto API

### Installation:
```bash
pnpm add @d1g1tal/krypton
```

### Usage:

#### Cipher Instances (Recommended)

Create cipher instances via `Krypton.create(algorithm)` for a streamlined, object-oriented API. Each cipher manages its own keys and algorithm parameters internally.

##### AesCipher

AES encryption with automatic IV management. A fresh IV is generated for each encryption and prepended to the ciphertext. On decryption, the IV is automatically extracted.

```typescript
import { Krypton } from '@d1g1tal/krypton';

// Create a new AES-GCM cipher (generates a new key)
const aes = await Krypton.create('AES-GCM');
const data = 'Hello World!';
const encrypted = await aes.encrypt(data);
const decrypted = await aes.decrypt(encrypted);

console.log(decrypted); // Hello World!
```

**Supported algorithms:** `AES-GCM` (recommended), `AES-CBC`, `AES-CTR`

```typescript
const aesCbc = await Krypton.create('AES-CBC');
const aesCtr = await Krypton.create('AES-CTR');
```

**Key import/export** — for persistent encryption across instances:
```typescript
import { Krypton, AesCipher } from '@d1g1tal/krypton';

// Export the key for later use
const aes = await Krypton.create('AES-GCM');
const jwk = await aes.exportKey();

// Later, recreate the instance from the saved key
const aes2 = await AesCipher.create('AES-GCM', jwk as JsonWebKey);
const decrypted = await aes2.decrypt(encrypted);
```

**Additional Authenticated Data (AAD)** for AES-GCM:
```typescript
const aes = await Krypton.create('AES-GCM');
const aad = Krypton.encode('header metadata');
const encrypted = await aes.encrypt('secret', aad);
const decrypted = await aes.decrypt(encrypted, aad);
```

##### RsaCipher

Asymmetric encryption/decryption using RSA-OAEP.

```typescript
const rsa = await Krypton.create('RSA-OAEP');
const encrypted = await rsa.encrypt('Secret');
const decrypted = await rsa.decrypt(encrypted);
```

##### HmacCipher

Message authentication via keyed hashing.

```typescript
const hmac = await Krypton.create('HMAC');
const signature = await hmac.sign('data');
const isValid = await hmac.verify(signature, 'data');
```

##### EcdsaCipher

Digital signatures using elliptic curve cryptography.

```typescript
const ecdsa = await Krypton.create('ECDSA');
const signature = await ecdsa.sign('data');
const isValid = await ecdsa.verify(signature, 'data');
```

##### EcdhCipher

Elliptic curve Diffie-Hellman key agreement for deriving shared secrets.

```typescript
const alice = await Krypton.create('ECDH');
const bob = await Krypton.create('ECDH');

// Exchange public keys
const alicePublicJwk = await alice.exportPublicKey();
const bobPublicJwk = await bob.exportPublicKey();
const alicePublicKey = await Krypton.importKey(alicePublicJwk, 'ECDH', 'jwk', { usages: [], namedCurve: 'P-256' });
const bobPublicKey = await Krypton.importKey(bobPublicJwk, 'ECDH', 'jwk', { usages: [], namedCurve: 'P-256' });

// Derive shared keys
const aliceSharedKey = await alice.deriveKey(bobPublicKey);
const bobSharedKey = await bob.deriveKey(alicePublicKey);
```

#### Krypton (Static API)
```typescript
import { Krypton } from '@d1g1tal/krypton';

const key = await Krypton.generateKey() as CryptoKey;
const parameters = Krypton.generateParameters();
const data = 'Hello World!';
const encrypted = await Krypton.encrypt(parameters, key, data);
const decrypted = await Krypton.decrypt(parameters, key, encrypted);

console.log(decrypted); // Hello World!
```

#### Hashing
```typescript
const hash = await Krypton.digest(Krypton.Hash.SHA_256, 'hello');
```

#### Key Derivation (PBKDF2)
```typescript
const baseKey = await Krypton.importKeyMaterial('my-password');
const salt = Krypton.randomValues(128);
const derivedKey = await Krypton.deriveKey(
  { name: Krypton.Algorithm.PBKDF2, salt, iterations: 600000, hash: Krypton.Hash.SHA_256 },
  baseKey,
  { name: Krypton.Algorithm.AES_GCM, length: 256 }
);
```

#### Key Export / Import
```typescript
const key = await Krypton.generateKey() as CryptoKey;
const jwk = await Krypton.exportKey(key, 'jwk');
const imported = await Krypton.importKey(jwk);
```

#### Key Wrapping
```typescript
const keyToWrap = await Krypton.generateKey() as CryptoKey;
const wrappingKey = await Krypton.generateKey(Krypton.Algorithm.AES_GCM, { usages: ['wrapKey', 'unwrapKey'] }) as CryptoKey;
const wrapParams = Krypton.generateParameters();
const wrapped = await Krypton.wrapKey('raw', keyToWrap, wrappingKey, wrapParams);
const unwrapped = await Krypton.unwrapKey('raw', wrapped, wrappingKey, wrapParams, { name: 'AES-GCM', length: 256 });
```

### API Reference

#### `Krypton` (Static Class)

| Method | Description |
|--------|-------------|
| `create(algorithm, options?)` | Creates a cipher instance (`AesCipher`, `RsaCipher`, `HmacCipher`, `EcdsaCipher`, `EcdhCipher`) |
| `encode(data)` | Encodes a string to `Uint8Array` |
| `decode(data)` | Decodes a `BufferSource` to string |
| `randomUUID()` | Generates a random UUID |
| `randomValues(size?)` | Generates cryptographic random values (default 128 bits) |
| `generateKey(algorithm?, options?)` | Generates a `CryptoKey` or `CryptoKeyPair` |
| `exportKey(key, format?)` | Exports a `CryptoKey` to JWK, raw, SPKI, or PKCS8 |
| `importKey(key, algorithm?, format?, options?)` | Imports a key from JWK or binary format |
| `encrypt(params, key, data)` | Encrypts data (string or `BufferSource`) |
| `decrypt(params, key, data)` | Decrypts data to a string |
| `generateParameters(algorithm?, options?)` | Generates algorithm parameters with random IV/nonce |
| `digest(algorithm?, data)` | Computes a hash (SHA-1, SHA-256, SHA-384, SHA-512) |
| `sign(algorithm, key, data)` | Signs data with HMAC or ECDSA |
| `verify(algorithm, key, signature, data)` | Verifies a signature |
| `deriveKey(algorithm, baseKey, derivedAlg, options?)` | Derives a key using PBKDF2 or HKDF |
| `importKeyMaterial(password, algorithm?)` | Imports raw key material for key derivation |
| `wrapKey(format, key, wrappingKey, algorithm)` | Wraps a `CryptoKey` |
| `unwrapKey(format, wrappedKey, unwrappingKey, unwrapAlg, keyAlg, options?)` | Unwraps a `CryptoKey` |

#### `AesCipher`

| Method | Description |
|--------|-------------|
| `AesCipher.create(algorithm, key?)` | Creates a new instance, optionally from an existing `CryptoKey` or `JsonWebKey` |
| `encrypt(data, additionalData?)` | Encrypts data (fresh IV per call, prepended to output) |
| `decrypt(data, additionalData?)` | Decrypts data (IV extracted automatically) |
| `exportKey(format?)` | Exports the instance's key |

#### `RsaCipher`

| Method | Description |
|--------|-------------|
| `RsaCipher.create(options?)` | Creates from generated or existing keys (`keyPair`, `publicKey`/`privateKey`, `hash`) |
| `encrypt(data, label?)` | Encrypts data using the public key |
| `decrypt(data, label?)` | Decrypts data using the private key |
| `exportPublicKey(format?)` | Exports the public key |
| `exportPrivateKey(format?)` | Exports the private key |

#### `HmacCipher`

| Method | Description |
|--------|-------------|
| `HmacCipher.create(options?)` | Creates from generated or existing key (`key`, `hash`) |
| `sign(data)` | Signs data using the HMAC key |
| `verify(signature, data)` | Verifies a signature |
| `exportKey(format?)` | Exports the key |

#### `EcdsaCipher`

| Method | Description |
|--------|-------------|
| `EcdsaCipher.create(options?)` | Creates from generated or existing keys (`keyPair`, `namedCurve`, `hash`) |
| `sign(data)` | Signs data using the private key |
| `verify(signature, data)` | Verifies a signature using the public key |
| `exportPublicKey(format?)` | Exports the public key |
| `exportPrivateKey(format?)` | Exports the private key |

#### `EcdhCipher`

| Method | Description |
|--------|-------------|
| `EcdhCipher.create(options?)` | Creates from generated or existing keys (`keyPair`, `namedCurve`) |
| `deriveKey(otherPartyPublicKey, derivedKeyAlg?, options?)` | Derives a shared key |
| `deriveBits(otherPartyPublicKey, length?)` | Derives raw bits from the shared secret |
| `exportPublicKey(format?)` | Exports the public key |
| `exportPrivateKey(format?)` | Exports the private key |

#### Constants

| Constant | Values |
|----------|--------|
| `Krypton.Algorithm` | `AES_CBC`, `AES_CTR`, `AES_GCM`, `RSA_OAEP`, `HMAC`, `ECDSA`, `ECDH`, `PBKDF2`, `HKDF` |
| `Krypton.Hash` | `SHA_1`, `SHA_256`, `SHA_384`, `SHA_512` |
| `Krypton.KeyFormat` | `JWK`, `RAW`, `SPKI`, `PKCS8` |
| `Krypton.KeyUsage` | `encrypt`, `decrypt`, `sign`, `verify`, `digest`, `deriveKey`, `deriveBits`, `wrapKey`, `unwrapKey` |
| `AesCipher.Mode` | `CBC`, `CTR`, `GCM` |