/**
 * Krypton is a simple wrapper around the Web Crypto API
 *
 * @module {Krypton} krypton
 * @author D1g1talEntr0py <jason.dimeo@gmail.com>
 */

import type { AesCipher } from './ciphers/aes.js';
import type { RsaCipher } from './ciphers/rsa.js';
import type { HmacCipher } from './ciphers/hmac.js';
import type { EcdsaCipher } from './ciphers/ecdsa.js';
import type { EcdhCipher } from './ciphers/ecdh.js';
import type { AesAlgorithm } from './types.js';

export type { AesCipher, RsaCipher, HmacCipher, EcdsaCipher, EcdhCipher, AesAlgorithm };
export type { AesMode, HashAlgorithm, NamedCurve, CipherAlgorithm, RsaHashAlgorithm, HmacHashAlgorithm, EcdsaHashAlgorithm, EcdsaNamedCurve, EcdhNamedCurve, EncryptionCipher, SigningCipher, TypedArray } from './types.js';

export type CipherMap = { [K in AesAlgorithm]: AesCipher } & {
	'RSA-OAEP': RsaCipher;
	'HMAC': HmacCipher;
	'ECDSA': EcdsaCipher;
	'ECDH': EcdhCipher;
};

/**
 * Krypton is a simple wrapper around the Web Crypto API that provides a unified interface for encryption, decryption, key management, and other cryptographic operations. It supports multiple algorithms including AES, RSA, HMAC, ECDSA, and ECDH.
 *
 * Create cipher instances using {@link Krypton.create} and perform operations like encryption, decryption, signing, and verification with ease. Krypton also includes utility methods for encoding/decoding, random value generation, and key derivation.
 *
 * @author D1g1talEntr0py <jason.dimeo@gmail.com>
 */
export class Krypton {
	private static textEncoder = new TextEncoder();
	private static textDecoder = new TextDecoder();

	static Algorithm = {
		AES_CBC: 'AES-CBC',
		AES_CTR: 'AES-CTR',
		AES_GCM: 'AES-GCM',
		RSA_OAEP: 'RSA-OAEP',
		HMAC: 'HMAC',
		ECDSA: 'ECDSA',
		ECDH: 'ECDH',
		PBKDF2: 'PBKDF2',
		HKDF: 'HKDF'
	} as const;

	static KeyFormat = {
		JWK: 'jwk',
		RAW: 'raw',
		SPKI: 'spki',
		PKCS8: 'pkcs8'
	} as const;

	static KeyUsage = {
		encrypt: 'encrypt',
		decrypt: 'decrypt',
		sign: 'sign',
		verify: 'verify',
		digest: 'digest',
		deriveKey: 'deriveKey',
		deriveBits: 'deriveBits',
		wrapKey: 'wrapKey',
		unwrapKey: 'unwrapKey'
	} as const;

	static Hash = {
		SHA_1: 'SHA-1',
		SHA_256: 'SHA-256',
		SHA_384: 'SHA-384',
		SHA_512: 'SHA-512'
	} as const;

	/**
	 * Encodes a string into a Uint8Array
	 *
	 * @param data - The string to encode
	 * @returns The encoded data as a Uint8Array
	 * @throws {Error} If the data cannot be encoded
	 */
	static encode(data: string): Uint8Array<ArrayBuffer> {
		return Krypton.textEncoder.encode(data);
	}

	/**
	 * Decodes a Uint8Array into a string
	 *
	 * @param data - The data to decode
	 * @returns The decoded string
	 * @throws {Error} If the data cannot be decoded
	 */
	static decode(data: BufferSource): string {
		return Krypton.textDecoder.decode(data);
	}

	/**
	 * Generates a random UUID
	 *
	 * @returns A random UUID
	 */
	static randomUUID(): string {
		return crypto.randomUUID();
	}

	/**
	 * Generates a random value of the specified size in bits (default: 128; maximum: 524288)
	 *
	 * @param size - The size of the random value in bits (default: 128)
	 * @returns A typed array containing the random values
	 * @throws {Error} If size is not a positive whole-byte integer within Web Crypto's 65536-byte limit
	 */
	static randomValues(size: number = 128): Uint32Array<ArrayBuffer> | Uint16Array<ArrayBuffer> | Uint8Array<ArrayBuffer> {
		if (!Number.isInteger(size) || size <= 0 || size > 524288 || size % 8 !== 0) {
			throw new Error(`Invalid size ${size}: must be a positive integer divisible by 8 and no greater than 524288 bits`);
		}

		const typedArray = Krypton.createTypedArray(size);
		return crypto.getRandomValues(typedArray);
	}

	/**
	 * Generates a cryptographic key for the specified algorithm (default: AES-GCM)
	 *
	 * @param algorithm - The algorithm to generate the key for (default: AES-GCM)
	 * @param options - Additional options for key generation. If usages are omitted, defaults are selected by algorithm.
	 * @returns A promise that resolves to the generated key
	 * @throws {Error} If the algorithm is not supported
	 */
	static async generateKey(algorithm: string = Krypton.Algorithm.AES_GCM, options: { extractable?: boolean; usages?: KeyUsage[]; hash?: string; namedCurve?: string; modulusLength?: number } = {}): Promise<CryptoKey | CryptoKeyPair> {
		const { extractable = true, hash, namedCurve, modulusLength } = options;
		const usages = options.usages ?? Krypton.defaultKeyUsages(algorithm);

		return await crypto.subtle.generateKey(Krypton.generateKeyParameters(algorithm, { hash, namedCurve, modulusLength }), extractable, usages);
	}

	/**
	 * Exports a CryptoKey to the specified format (default: JWK)
	 *
	 * @param key - The key to export
	 * @param format - The format to export the key in (default: JWK)
	 * @returns A promise that resolves to JsonWebKey when format is 'jwk', otherwise ArrayBuffer
	 * @throws {Error} If the format is not supported
	 */
	static async exportKey<F extends KeyFormat = 'jwk'>(key: CryptoKey, format?: F): Promise<F extends 'jwk' ? JsonWebKey : ArrayBuffer> {
		return await crypto.subtle.exportKey(format ?? Krypton.KeyFormat.JWK, key) as F extends 'jwk' ? JsonWebKey : ArrayBuffer;
	}

	/**
	 * Creates a new cipher instance for the specified algorithm.
	 * The cipher module is loaded on first use, so only the ciphers you create are downloaded.
	 *
	 * @param algorithm - The algorithm to create a cipher for (e.g., 'AES-GCM', 'RSA-OAEP', 'HMAC', 'ECDSA', 'ECDH')
	 * @param options - Optional configuration for the cipher
	 * @returns A promise that resolves to the appropriate cipher instance
	 */
	static async create<A extends keyof CipherMap>(algorithm: A, options?: Record<string, unknown>): Promise<CipherMap[A]> {
		switch (algorithm) {
			case Krypton.Algorithm.AES_CBC:
			case Krypton.Algorithm.AES_CTR:
			case Krypton.Algorithm.AES_GCM: return await (await import('./ciphers/aes.js')).AesCipher.create(algorithm, options?.key as CryptoKey | JsonWebKey | undefined) as CipherMap[A];
			case Krypton.Algorithm.RSA_OAEP: return await (await import('./ciphers/rsa.js')).RsaCipher.create(options) as CipherMap[A];
			case Krypton.Algorithm.HMAC: return await (await import('./ciphers/hmac.js')).HmacCipher.create(options) as CipherMap[A];
			case Krypton.Algorithm.ECDSA: return await (await import('./ciphers/ecdsa.js')).EcdsaCipher.create(options) as CipherMap[A];
			case Krypton.Algorithm.ECDH: return await (await import('./ciphers/ecdh.js')).EcdhCipher.create(options) as CipherMap[A];
			default: throw new Error(`Unsupported cipher algorithm: ${algorithm}`);
		}
	}

	/**
	 * Imports a key from the specified format (default: JWK)
	 *
	 * @param key - The key to import
	 * @param algorithm - The algorithm to use for the imported key (default: AES-GCM)
	 * @param format - The format of the key being imported (default: JWK)
	 * @param options - Additional options for key import. RSA-OAEP, ECDSA, and ECDH require explicit usages.
	 * @returns A promise that resolves to the imported key
	 * @throws {Error} If the format is not supported or asymmetric-key usages are omitted
	 */
	static async importKey(key: JsonWebKey | BufferSource, algorithm: string = Krypton.Algorithm.AES_GCM, format: KeyFormat = Krypton.KeyFormat.JWK, options: { extractable?: boolean; usages?: KeyUsage[]; hash?: string; namedCurve?: string } = {}): Promise<CryptoKey> {
		const { extractable = true, hash, namedCurve } = options;
		const usages = options.usages ?? Krypton.defaultImportKeyUsages(algorithm);
		const keyParams = Krypton.generateKeyParameters(algorithm, { hash, namedCurve });

		if (format === Krypton.KeyFormat.JWK) {
			return await crypto.subtle.importKey(format, key as JsonWebKey, keyParams, extractable, usages);
		}

		return await crypto.subtle.importKey(format, key as BufferSource, keyParams, extractable, usages);

	}

	/**
	 * Encrypts the data using the specified parameters and key
	 *
	 * @param parameters - The parameters to use for encryption
	 * @param key - The key to use for encryption
	 * @param data - The data to encrypt (string or BufferSource)
	 * @returns A promise that resolves to the encrypted data as an ArrayBuffer
	 * @throws {Error} If the encryption fails
	 */
	static async encrypt(parameters: AesCtrParams | AesCbcParams | AesGcmParams | RsaOaepParams, key: CryptoKey, data: string | BufferSource): Promise<ArrayBuffer> {
		return await crypto.subtle.encrypt(parameters, key, typeof data === 'string' ? Krypton.textEncoder.encode(data) : data);
	}

	/**
	 * Decrypts the data using the specified parameters and key
	 *
	 * @param parameters - The parameters to use for decryption
	 * @param key - The key to use for decryption
	 * @param data - The data to decrypt
	 * @returns A promise that resolves to the decrypted data as a string
	 * @throws {Error} If the decryption fails
	 */
	static async decrypt(parameters: AesCtrParams | AesCbcParams | AesGcmParams | RsaOaepParams, key: CryptoKey, data: BufferSource): Promise<string> {
		return Krypton.textDecoder.decode(await Krypton.decryptBytes(parameters, key, data));
	}

	/**
	 * Decrypts data without interpreting the plaintext as UTF-8.
	 *
	 * @param parameters - The parameters to use for decryption
	 * @param key - The key to use for decryption
	 * @param data - The data to decrypt
	 * @returns A promise that resolves to the decrypted bytes as an ArrayBuffer
	 * @throws {Error} If the decryption fails
	 */
	static async decryptBytes(parameters: AesCtrParams | AesCbcParams | AesGcmParams | RsaOaepParams, key: CryptoKey, data: BufferSource): Promise<ArrayBuffer> {
		return await crypto.subtle.decrypt(parameters, key, data);
	}

	/**
	 * Generates the parameters for the encryption/decryption
	 *
	 * @param algorithm - The algorithm to use
	 * @param options - Additional options (e.g., additionalData for GCM)
	 * @returns The parameters for the encryption/decryption
	 * @throws {Error} If the algorithm is not supported
	 */
	static generateParameters(algorithm: string = Krypton.Algorithm.AES_GCM, options?: { additionalData?: BufferSource }): AesCtrParams | AesCbcParams | AesGcmParams | RsaOaepParams {
		switch (algorithm) {
			case Krypton.Algorithm.AES_CTR:
			case Krypton.Algorithm.AES_CBC: {
				if (options?.additionalData !== undefined) {
					throw new Error('additionalData is only supported with AES-GCM');
				}

				return algorithm === Krypton.Algorithm.AES_CTR
					? { name: algorithm, counter: Krypton.randomValues(), length: 128 }
					: { name: algorithm, iv: Krypton.randomValues() };
			}
			case Krypton.Algorithm.AES_GCM: {
				const params: AesGcmParams = { name: algorithm, iv: Krypton.randomValues(96), tagLength: 128 };
				if (options?.additionalData !== undefined) { params.additionalData = options.additionalData }

				return params;
			}
			case Krypton.Algorithm.RSA_OAEP: return { name: algorithm };
			default: throw new Error(`Unsupported algorithm ${algorithm}`);
		}
	}

	/**
	 * Creates a typed array of the specified size in bits (default: 128)
	 *
	 * @param size - The size of the typed array in bits (default: 128)
	 * @returns A typed array of the specified size
	 * @throws {Error} If the size is invalid
	 */
	private static createTypedArray(size: number = 128): Uint32Array<ArrayBuffer> | Uint16Array<ArrayBuffer> | Uint8Array<ArrayBuffer> {
		switch (true) {
			case size % 32 === 0: return new Uint32Array(size / 32);
			case size % 16 === 0: return new Uint16Array(size / 16);
			case size % 8 === 0: return new Uint8Array(size / 8);
			default: throw new Error(`Invalid size ${size}`);
		}
	}

	/**
	 * Returns the default usages for key generation, preserving the legacy AES/RSA defaults.
	 *
	 * @param algorithm - The key algorithm
	 * @returns The algorithm-appropriate key usages
	 */
	private static defaultKeyUsages(algorithm: string): KeyUsage[] {
		switch (algorithm) {
			case Krypton.Algorithm.AES_CBC:
			case Krypton.Algorithm.AES_CTR:
			case Krypton.Algorithm.AES_GCM:
			case Krypton.Algorithm.RSA_OAEP: return [Krypton.KeyUsage.encrypt, Krypton.KeyUsage.decrypt];
			case Krypton.Algorithm.HMAC:
			case Krypton.Algorithm.ECDSA: return [Krypton.KeyUsage.sign, Krypton.KeyUsage.verify];
			case Krypton.Algorithm.ECDH: return [Krypton.KeyUsage.deriveKey, Krypton.KeyUsage.deriveBits];
			default: return [Krypton.KeyUsage.encrypt, Krypton.KeyUsage.decrypt];
		}
	}

	/**
	 * Returns safe defaults for key import, rejecting asymmetric algorithms whose
	 * valid usages depend on whether the imported key is public or private.
	 *
	 * @param algorithm - The key algorithm
	 * @returns The algorithm-appropriate key usages
	 * @throws {Error} If usages must be specified for an asymmetric key
	 */
	private static defaultImportKeyUsages(algorithm: string): KeyUsage[] {
		switch (algorithm) {
			case Krypton.Algorithm.AES_CBC:
			case Krypton.Algorithm.AES_CTR:
			case Krypton.Algorithm.AES_GCM: return [Krypton.KeyUsage.encrypt, Krypton.KeyUsage.decrypt];
			case Krypton.Algorithm.HMAC: return [Krypton.KeyUsage.sign, Krypton.KeyUsage.verify];
			case Krypton.Algorithm.RSA_OAEP:
			case Krypton.Algorithm.ECDSA:
			case Krypton.Algorithm.ECDH:
				throw new Error(`Explicit usages are required when importing ${algorithm} keys; valid usages depend on whether the key is public or private`);
			default: return [Krypton.KeyUsage.encrypt, Krypton.KeyUsage.decrypt];
		}
	}

	/**
	 * Generates the parameters for key generation based on the specified algorithm
	 *
	 * @param algorithm - The algorithm to generate the key for
	 * @param options - Additional options (e.g., hash algorithm, named curve)
	 * @returns The parameters for key generation
	 * @throws {Error} If the algorithm is not supported
	 */
	private static generateKeyParameters(algorithm: string, options?: { hash?: string; namedCurve?: string; modulusLength?: number }): AesKeyGenParams | RsaHashedKeyGenParams | HmacKeyGenParams | EcKeyGenParams {
		switch (algorithm) {
			case Krypton.Algorithm.AES_CTR:
			case Krypton.Algorithm.AES_CBC:
			case Krypton.Algorithm.AES_GCM: return { name: algorithm, length: 256 };
			case Krypton.Algorithm.RSA_OAEP: return { name: algorithm, modulusLength: options?.modulusLength ?? 4096, publicExponent: new Uint8Array([1, 0, 1]), hash: options?.hash ?? Krypton.Hash.SHA_512 };
			case Krypton.Algorithm.HMAC: return { name: algorithm, hash: options?.hash ?? Krypton.Hash.SHA_256 };
			case Krypton.Algorithm.ECDSA: return { name: algorithm, namedCurve: options?.namedCurve ?? 'P-256' };
			case Krypton.Algorithm.ECDH: return { name: algorithm, namedCurve: options?.namedCurve ?? 'P-256' };
			default: throw new Error(`Unsupported algorithm ${algorithm}`);
		}
	}

	/**
	 * Computes a digest (hash) of the data using the specified algorithm
	 *
	 * @param algorithm - The hash algorithm to use (e.g., SHA-256, SHA-512)
	 * @param data - The data to hash (string or BufferSource)
	 * @returns A promise that resolves to the hash as an ArrayBuffer
	 */
	static async digest(algorithm: string = Krypton.Hash.SHA_256, data: string | BufferSource): Promise<ArrayBuffer> {
		const encodedData = typeof data === 'string' ? Krypton.textEncoder.encode(data) : data;
		return await crypto.subtle.digest(algorithm, encodedData);
	}

	/**
	 * Signs data using the specified algorithm and key
	 *
	 * @param algorithm - The algorithm parameters to use for signing
	 * @param key - The key to use for signing
	 * @param data - The data to sign (string or BufferSource)
	 * @returns A promise that resolves to the signature as an ArrayBuffer
	 */
	static async sign(algorithm: AlgorithmIdentifier | RsaPssParams | EcdsaParams, key: CryptoKey, data: string | BufferSource): Promise<ArrayBuffer> {
		const encodedData = typeof data === 'string' ? Krypton.textEncoder.encode(data) : data;
		return await crypto.subtle.sign(algorithm, key, encodedData);
	}

	/**
	 * Verifies a signature using the specified algorithm and key
	 *
	 * @param algorithm - The algorithm parameters to use for verification
	 * @param key - The key to use for verification
	 * @param signature - The signature to verify
	 * @param data - The data that was signed (string or BufferSource)
	 * @returns A promise that resolves to true if the signature is valid
	 */
	static async verify(algorithm: AlgorithmIdentifier | RsaPssParams | EcdsaParams, key: CryptoKey, signature: BufferSource, data: string | BufferSource): Promise<boolean> {
		const encodedData = typeof data === 'string' ? Krypton.textEncoder.encode(data) : data;
		return await crypto.subtle.verify(algorithm, key, signature, encodedData);
	}

	/**
	 * Derives a cryptographic key from a base key using the specified algorithm
	 *
	 * @param algorithm - The key derivation algorithm parameters (e.g., PBKDF2, HKDF)
	 * @param baseKey - The base key to derive from
	 * @param derivedKeyAlgorithm - The algorithm for the derived key
	 * @param options - Additional options for the derived key
	 * @returns A promise that resolves to the derived key
	 */
	static async deriveKey(algorithm: Pbkdf2Params | HkdfParams, baseKey: CryptoKey, derivedKeyAlgorithm: AesKeyGenParams | HmacKeyGenParams, { extractable = false, usages = [Krypton.KeyUsage.encrypt, Krypton.KeyUsage.decrypt] }: { extractable?: boolean; usages?: KeyUsage[] } = {}): Promise<CryptoKey> {
		return await crypto.subtle.deriveKey(algorithm, baseKey, derivedKeyAlgorithm, extractable, usages);
	}

	/**
	 * Imports a raw key for use with key derivation algorithms (PBKDF2, HKDF)
	 *
	 * @param password - The password or key material to import
	 * @param algorithm - The algorithm to use (PBKDF2 or HKDF)
	 * @returns A promise that resolves to the imported base key
	 */
	static async importKeyMaterial(password: string | BufferSource, algorithm: string = Krypton.Algorithm.PBKDF2): Promise<CryptoKey> {
		const keyData = typeof password === 'string' ? Krypton.textEncoder.encode(password) : password;
		return await crypto.subtle.importKey('raw', keyData, algorithm, false, [Krypton.KeyUsage.deriveKey, Krypton.KeyUsage.deriveBits]);
	}

	/**
	 * Wraps a CryptoKey using another key
	 *
	 * @param format - The format of the key to wrap
	 * @param key - The key to wrap
	 * @param wrappingKey - The key to use for wrapping
	 * @param wrapAlgorithm - The algorithm to use for wrapping
	 * @returns A promise that resolves to the wrapped key as an ArrayBuffer
	 */
	static async wrapKey(format: KeyFormat, key: CryptoKey, wrappingKey: CryptoKey, wrapAlgorithm: AlgorithmIdentifier | RsaOaepParams | AesCtrParams | AesCbcParams | AesGcmParams): Promise<ArrayBuffer> {
		return await crypto.subtle.wrapKey(format, key, wrappingKey, wrapAlgorithm);
	}

	/**
	 * Unwraps a previously wrapped CryptoKey
	 *
	 * @param format - The format of the wrapped key
	 * @param wrappedKey - The wrapped key data
	 * @param unwrappingKey - The key to use for unwrapping
	 * @param unwrapAlgorithm - The algorithm used when the key was wrapped
	 * @param unwrappedKeyAlgorithm - The algorithm of the unwrapped key
	 * @param options - Additional options for the unwrapped key
	 * @returns A promise that resolves to the unwrapped CryptoKey
	 */
	static async unwrapKey(format: KeyFormat, wrappedKey: BufferSource, unwrappingKey: CryptoKey, unwrapAlgorithm: AlgorithmIdentifier | RsaOaepParams | AesCtrParams | AesCbcParams | AesGcmParams, unwrappedKeyAlgorithm: AlgorithmIdentifier | AesKeyGenParams | HmacKeyGenParams | RsaHashedImportParams | EcKeyImportParams, { extractable = true, usages = [Krypton.KeyUsage.encrypt, Krypton.KeyUsage.decrypt] }: { extractable?: boolean; usages?: KeyUsage[] } = {}): Promise<CryptoKey> {
		return await crypto.subtle.unwrapKey(format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, usages);
	}
}