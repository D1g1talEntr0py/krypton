import { Krypton } from '../krypton.js';
import type { HmacHashAlgorithm, SigningCipher } from '../types.js';

/**
 * HMAC cipher for the Web Crypto API.
 * Provides message authentication via keyed hashing (sign/verify).
 *
 * Create instances via {@link Krypton.create}.
 *
 * @author D1g1talEntr0py <jason.dimeo@gmail.com>
 */
export class HmacCipher implements SigningCipher {
	private readonly key: CryptoKey;

	/**
	 * @param key - The CryptoKey to use for signing and verification
	 */
	private constructor(key: CryptoKey) {
		this.key = key;
	}

	/**
	 * Creates a new HmacCipher instance
	 *
	 * @param options - Optional configuration including an existing key or hash algorithm
	 * @returns A promise that resolves to a new HmacCipher instance
	 */
	static async create(options?: { key?: CryptoKey | JsonWebKey; hash?: HmacHashAlgorithm }): Promise<HmacCipher> {
		const hash = options?.hash ?? Krypton.Hash.SHA_256;

		if (options?.key instanceof CryptoKey) {
			return new HmacCipher(options.key);
		}

		if (options?.key) {
			const importedKey = await Krypton.importKey(options.key, Krypton.Algorithm.HMAC, Krypton.KeyFormat.JWK, { usages: ['sign', 'verify'], hash });

			return new HmacCipher(importedKey);
		}

		const generatedKey = await Krypton.generateKey(Krypton.Algorithm.HMAC, { usages: ['sign', 'verify'], hash }) as CryptoKey;

		return new HmacCipher(generatedKey);
	}

	/**
	 * Exports the current key in the specified format
	 *
	 * @param format - The format to export the key in (default: JWK)
	 * @returns A promise that resolves to JsonWebKey when format is 'jwk', otherwise ArrayBuffer
	 */
	async exportKey<F extends KeyFormat = 'jwk'>(format?: F): Promise<F extends 'jwk' ? JsonWebKey : ArrayBuffer> {
		return await Krypton.exportKey(this.key, format);
	}

	/**
	 * Signs data using the HMAC key
	 *
	 * @param data - The data to sign
	 * @returns The signature as an ArrayBuffer
	 */
	async sign(data: string | BufferSource): Promise<ArrayBuffer> {
		return await Krypton.sign(Krypton.Algorithm.HMAC, this.key, data);
	}

	/**
	 * Verifies a signature against data using the HMAC key
	 *
	 * @param signature - The signature to verify
	 * @param data - The data that was signed
	 * @returns true if the signature is valid
	 */
	async verify(signature: BufferSource, data: string | BufferSource): Promise<boolean> {
		return await Krypton.verify(Krypton.Algorithm.HMAC, this.key, signature, data);
	}
}
