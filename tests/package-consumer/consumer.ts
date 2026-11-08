import { Krypton, type AesCipher as RootAesCipher, type CipherAlgorithm } from '@d1g1tal/krypton';
import { AesCipher } from '@d1g1tal/krypton/ciphers/aes';
import { EcdhCipher } from '@d1g1tal/krypton/ciphers/ecdh';
import { EcdsaCipher } from '@d1g1tal/krypton/ciphers/ecdsa';
import { HmacCipher } from '@d1g1tal/krypton/ciphers/hmac';
import { RsaCipher } from '@d1g1tal/krypton/ciphers/rsa';

const algorithm: CipherAlgorithm = Krypton.Algorithm.AES_GCM;
const rootAes: Promise<RootAesCipher> = Krypton.create(algorithm);
const rootRsa: Promise<RsaCipher> = Krypton.create('RSA-OAEP', { hash: 'SHA-256', modulusLength: 2048 });
const rootEcdsa: Promise<EcdsaCipher> = Krypton.create('ECDSA', { namedCurve: 'P-384', hash: 'SHA-384' });

// @ts-expect-error RSA-OAEP does not accept an elliptic-curve option.
Krypton.create('RSA-OAEP', { namedCurve: 'P-384' });
// @ts-expect-error ECDSA does not accept an RSA modulus option.
Krypton.create('ECDSA', { modulusLength: 2048 });

const aes: Promise<AesCipher> = AesCipher.create('AES-CTR');
const rsa: Promise<RsaCipher> = RsaCipher.create({ hash: 'SHA-512', modulusLength: 3072 });
const hmac: Promise<HmacCipher> = HmacCipher.create({ hash: 'SHA-384' });
const ecdsa: Promise<EcdsaCipher> = EcdsaCipher.create({ namedCurve: 'P-521', hash: 'SHA-512' });
const ecdh: Promise<EcdhCipher> = EcdhCipher.create({ namedCurve: 'P-384' });

// @ts-expect-error HMAC does not accept an ECDH curve option.
HmacCipher.create({ namedCurve: 'P-256' });
// @ts-expect-error ECDH does not accept a signing hash option.
EcdhCipher.create({ hash: 'SHA-256' });

const aesInstance = await aes;
const aesJwk: Promise<JsonWebKey> = aesInstance.exportKey();
const aesRaw: Promise<ArrayBuffer> = aesInstance.exportKey('raw');
const aesCiphertext: Promise<ArrayBuffer> = aesInstance.encrypt('consumer fixture');
const aesPlaintext: Promise<string> = aesInstance.decrypt(new ArrayBuffer(0));

const rsaInstance = await rsa;
const rsaPublicJwk: Promise<JsonWebKey> = rsaInstance.exportPublicKey();
const rsaPrivateRaw: Promise<ArrayBuffer> = rsaInstance.exportPrivateKey('pkcs8');
const rsaPlaintext: Promise<string> = rsaInstance.decrypt(new ArrayBuffer(0));

const hmacInstance = await hmac;
const hmacSignature: Promise<ArrayBuffer> = hmacInstance.sign('consumer fixture');
const hmacValid: Promise<boolean> = hmacInstance.verify(new ArrayBuffer(0), 'consumer fixture');

const ecdsaInstance = await ecdsa;
const ecdsaSignature: Promise<ArrayBuffer> = ecdsaInstance.sign('consumer fixture');
const ecdsaValid: Promise<boolean> = ecdsaInstance.verify(new ArrayBuffer(0), 'consumer fixture');

const ecdhInstance = await ecdh;
declare const peerPublicKey: CryptoKey;
const sharedKey: Promise<CryptoKey> = ecdhInstance.deriveKey(peerPublicKey);
const sharedBits: Promise<ArrayBuffer> = ecdhInstance.deriveBits(peerPublicKey);

void [rootAes, rootRsa, rootEcdsa, aesJwk, aesRaw, aesCiphertext, aesPlaintext, rsaPublicJwk, rsaPrivateRaw, rsaPlaintext, hmacSignature, hmacValid, ecdsaSignature, ecdsaValid, sharedKey, sharedBits];
