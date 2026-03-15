import { Krypton } from '../krypton.js';
import type { AesAlgorithm, AesMode, EncryptionCipher } from '../types.js';

/**
 * AES cipher for the Web Crypto API.
 * Generates a fresh IV/nonce for each encryption and prepends it to the ciphertext.
 * On decryption, the IV is extracted from the ciphertext automatically.
 *
 * Create instances via {@link Krypton.create}.
 *
 * @author D1g1talEntr0py <jason.dimeo@gmail.com>
 */
export class AesCipher implements EncryptionCipher {
	private readonly key: CryptoKey;
	private readonly algorithm: AesAlgorithm;
	private readonly mode: AesMode;

	/**
	 * @param key - The CryptoKey to use for encryption and decryption
	 * @param algorithm - The AES algorithm (e.g., 'AES-GCM')
	 */
	private constructor(key: CryptoKey, algorithm: AesAlgorithm) {
		this.key = key;
		this.algorithm = algorithm;
		this.mode = algorithm.slice(4) as AesMode;
	}

	static Mode = {
		CBC: 'CBC',
		CTR: 'CTR',
		GCM: 'GCM'
	} as const;

	/**
	 * Creates a new AesCipher instance
	 *
	 * @param algorithm - The AES algorithm to use
	 * @param key - Optional existing CryptoKey or JsonWebKey. If omitted, a new key is generated.
	 * @returns A promise that resolves to a new AesCipher instance
	 */
	static async create(algorithm: AesAlgorithm, key?: CryptoKey | JsonWebKey): Promise<AesCipher> {
		if (key instanceof CryptoKey) { return new AesCipher(key, algorithm) }

		if (key) {
			const importedKey = await Krypton.importKey(key, algorithm);

			return new AesCipher(importedKey, algorithm);
		}

		const generatedKey = await Krypton.generateKey(algorithm) as CryptoKey;

		return new AesCipher(generatedKey, algorithm);
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
	 * Encrypts the data using the algorithm specified when the AesCipher was created.
	 * A fresh IV/nonce is generated for each call and prepended to the ciphertext.
	 *
	 * @param data - The data to encrypt
	 * @param additionalData - Optional additional authenticated data (only for GCM mode)
	 * @returns The encrypted data as an ArrayBuffer with the IV prepended
	 * @throws {Error} If the encryption fails
	 */
	async encrypt(data: string | BufferSource, additionalData?: BufferSource): Promise<ArrayBuffer> {
		const parameters = AesCipher.generateParameters(this.algorithm, this.mode, additionalData);
		const iv = AesCipher.extractIv(parameters);
		const cipherText = await Krypton.encrypt(parameters, this.key, data);

		const result = new Uint8Array(iv.byteLength + cipherText.byteLength);
		result.set(iv, 0);
		result.set(new Uint8Array(cipherText), iv.byteLength);

		return result.buffer;
	}

	/**
	 * Decrypts the data using the algorithm specified when the AesCipher was created.
	 * Expects the IV to be prepended to the cipher text (as produced by {@link encrypt}).
	 *
	 * @param data - The data to decrypt (with IV prepended)
	 * @param additionalData - Optional additional authenticated data (only for GCM mode)
	 * @returns The decrypted data as a string
	 * @throws {Error} If the decryption fails
	 */
	async decrypt(data: BufferSource, additionalData?: BufferSource): Promise<string> {
		const dataBytes = data instanceof ArrayBuffer	? new Uint8Array(data) : new Uint8Array((data as ArrayBufferView).buffer, (data as ArrayBufferView).byteOffset, (data as ArrayBufferView).byteLength);
		const ivLength = AesCipher.getIvLength(this.mode);
		const parameters = AesCipher.rebuildParameters(this.algorithm, this.mode, dataBytes.slice(0, ivLength), additionalData);

		return await Krypton.decrypt(parameters, this.key, dataBytes.slice(ivLength));
	}

	/**
	 * Returns the IV byte length for a given mode
	 *
	 * @param mode - The AES mode
	 * @returns The IV length in bytes
	 */
	private static getIvLength(mode: AesMode): number {
		switch (mode) {
			case AesCipher.Mode.GCM: return 12; // 96 bits
			case AesCipher.Mode.CBC:
			case AesCipher.Mode.CTR: return 16; // 128 bits
		}
	}

	/**
	 * Extracts the IV/counter from encryption parameters
	 *
	 * @param parameters - The encryption parameters
	 * @returns The IV as a Uint8Array
	 */
	private static extractIv(parameters: AesCtrParams | AesCbcParams | AesGcmParams): Uint8Array<ArrayBuffer> {
		const source = 'counter' in parameters ? parameters.counter : parameters.iv;

		return source instanceof ArrayBuffer ? new Uint8Array(source) : new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
	}

	/**
	 * Generates fresh parameters for encryption based on the specified algorithm and mode
	 *
	 * @param algorithm - The algorithm to use for encryption and decryption
	 * @param mode - The mode to use for encryption and decryption
	 * @param additionalData - Optional additional authenticated data (GCM only)
	 * @returns The parameters for encryption and decryption
	 * @throws {Error} If the mode is not supported
	 */
	private static generateParameters(algorithm: AesAlgorithm, mode: AesMode, additionalData?: BufferSource): AesCtrParams | AesCbcParams | AesGcmParams {
		switch (mode) {
			case AesCipher.Mode.CTR: return { name: algorithm, counter: Krypton.randomValues(), length: 128 };
			case AesCipher.Mode.CBC: return { name: algorithm, iv: Krypton.randomValues() };
			case AesCipher.Mode.GCM: {
				const params: AesGcmParams = { name: algorithm, iv: Krypton.randomValues(96), tagLength: 128 };
				if (additionalData) { params.additionalData = additionalData }

				return params;
			}
		}
	}

	/**
	 * Rebuilds parameters for decryption using the extracted IV
	 *
	 * @param algorithm - The algorithm name
	 * @param mode - The AES mode
	 * @param iv - The extracted IV
	 * @param additionalData - Optional additional authenticated data (GCM only)
	 * @returns The parameters for decryption
	 */
	private static rebuildParameters(algorithm: AesAlgorithm, mode: AesMode, iv: Uint8Array<ArrayBuffer>, additionalData?: BufferSource): AesCtrParams | AesCbcParams | AesGcmParams {
		switch (mode) {
			case AesCipher.Mode.CTR: return { name: algorithm, counter: iv, length: 128 };
			case AesCipher.Mode.CBC: return { name: algorithm, iv };
			case AesCipher.Mode.GCM: {
				const params: AesGcmParams = { name: algorithm, iv, tagLength: 128 };
				if (additionalData) { params.additionalData = additionalData }

				return params;
			}
		}
	}
}