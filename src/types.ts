// Base template literal types
export type AesMode = 'CBC' | 'CTR' | 'GCM';
export type AesAlgorithm = `AES-${AesMode}`;
export type HashAlgorithm = `SHA-${1 | 256 | 384 | 512}`;
export type NamedCurve = `P-${256 | 384 | 521}`;
export type CipherAlgorithm = AesAlgorithm | 'RSA-OAEP' | 'HMAC' | 'ECDSA' | 'ECDH';

// Cipher-specific algorithm types derived from base types
export type RsaHashAlgorithm = HashAlgorithm;
export type HmacHashAlgorithm = HashAlgorithm;
export type EcdsaHashAlgorithm = Exclude<HashAlgorithm, 'SHA-1'>;
export type EcdsaNamedCurve = NamedCurve;
export type EcdhNamedCurve = NamedCurve;

/**
 * Interface for ciphers that provide encryption and decryption.
 * Implemented by {@link AesCipher} and {@link RsaCipher}.
 */
export interface EncryptionCipher {
	encrypt: (data: string | BufferSource) => Promise<ArrayBuffer>;
	decrypt: (data: BufferSource) => Promise<string>;
}

/**
 * Interface for ciphers that provide signing and verification.
 * Implemented by {@link HmacCipher} and {@link EcdsaCipher}.
 */
export interface SigningCipher {
	sign: (data: string | BufferSource) => Promise<ArrayBuffer>;
	verify: (signature: BufferSource, data: string | BufferSource) => Promise<boolean>;
}

export type TypedArray = Int8Array | Uint8Array | Uint8ClampedArray | Int16Array | Uint16Array | Int32Array | Uint32Array | Float32Array | Float64Array | BigInt64Array | BigUint64Array;