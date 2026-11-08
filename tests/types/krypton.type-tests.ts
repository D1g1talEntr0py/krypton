import { Krypton } from '../../src/krypton.js';
import type { AesCipher, EcdhCipher, EcdsaCipher, HmacCipher, RsaCipher } from '../../src/krypton.js';

declare const key: CryptoKey;
declare const keyPair: CryptoKeyPair;
declare const jwk: JsonWebKey;

const aesCipher: Promise<AesCipher> = Krypton.create('AES-GCM', { key });
const aesCipherFromJwk: Promise<AesCipher> = Krypton.create('AES-CBC', { key: jwk });
const rsaCipher: Promise<RsaCipher> = Krypton.create('RSA-OAEP', { keyPair, hash: 'SHA-256', modulusLength: 2048 });
const rsaCipherFromKeys: Promise<RsaCipher> = Krypton.create('RSA-OAEP', { publicKey: key, privateKey: key });
const hmacCipher: Promise<HmacCipher> = Krypton.create('HMAC', { key, hash: 'SHA-384' });
const ecdsaCipher: Promise<EcdsaCipher> = Krypton.create('ECDSA', { keyPair, namedCurve: 'P-256', hash: 'SHA-256' });
const ecdhCipher: Promise<EcdhCipher> = Krypton.create('ECDH', { keyPair, namedCurve: 'P-384' });

// @ts-expect-error AES options do not accept hash
Krypton.create('AES-GCM', { hash: 'SHA-256' });
// @ts-expect-error RSA-OAEP options do not accept namedCurve
Krypton.create('RSA-OAEP', { namedCurve: 'P-256' });
// @ts-expect-error HMAC options do not accept keyPair
Krypton.create('HMAC', { keyPair });
// @ts-expect-error ECDSA options do not accept modulusLength
Krypton.create('ECDSA', { modulusLength: 2048 });
// @ts-expect-error ECDH options do not accept hash
Krypton.create('ECDH', { hash: 'SHA-256' });

void [aesCipher, aesCipherFromJwk, rsaCipher, rsaCipherFromKeys, hmacCipher, ecdsaCipher, ecdhCipher];
