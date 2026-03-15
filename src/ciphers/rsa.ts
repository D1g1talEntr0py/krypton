import { Krypton } from '../krypton.js';
import type { EncryptionCipher, RsaHashAlgorithm } from '../types.js';

/**
 * RSA-OAEP cipher for the Web Crypto API.
 * Provides asymmetric encryption/decryption using an RSA key pair.
 *
 * Create instances via {@link Krypton.create}.
 *
 * @author D1g1talEntr0py <jason.dimeo@gmail.com>
 */
export class RsaCipher implements EncryptionCipher {
	private readonly publicKey: CryptoKey;
	private readonly privateKey: CryptoKey;

	/**
	 * @param publicKey - The public key for encryption
	 * @param privateKey - The private key for decryption
	 */
	private constructor(publicKey: CryptoKey, privateKey: CryptoKey) {
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}

	/**
	 * Creates a new RsaCipher instance
	 *
	 * @param options - Optional configuration including existing keys or hash algorithm
	 * @returns A promise that resolves to a new RsaCipher instance
	 */
	static async create(options?: { keyPair?: CryptoKeyPair; publicKey?: CryptoKey; privateKey?: CryptoKey; hash?: RsaHashAlgorithm; modulusLength?: number }): Promise<RsaCipher> {
		if (options?.keyPair) {
			return new RsaCipher(options.keyPair.publicKey, options.keyPair.privateKey);
		}

		if (options?.publicKey && options?.privateKey) {
			return new RsaCipher(options.publicKey, options.privateKey);
		}

		const keyPair = await Krypton.generateKey(Krypton.Algorithm.RSA_OAEP, { usages: ['encrypt', 'decrypt'] }) as CryptoKeyPair;

		return new RsaCipher(keyPair.publicKey, keyPair.privateKey);
	}

	/**
	 * Exports the public key in the specified format
	 *
	 * @param format - The format to export the key in (default: JWK)
	 * @returns A promise that resolves to JsonWebKey when format is 'jwk', otherwise ArrayBuffer
	 */
	async exportPublicKey<F extends KeyFormat = 'jwk'>(format?: F): Promise<F extends 'jwk' ? JsonWebKey : ArrayBuffer> {
		return await Krypton.exportKey(this.publicKey, format);
	}

	/**
	 * Exports the private key in the specified format
	 *
	 * @param format - The format to export the key in (default: JWK)
	 * @returns A promise that resolves to JsonWebKey when format is 'jwk', otherwise ArrayBuffer
	 */
	async exportPrivateKey<F extends KeyFormat = 'jwk'>(format?: F): Promise<F extends 'jwk' ? JsonWebKey : ArrayBuffer> {
		return await Krypton.exportKey(this.privateKey, format);
	}

	/**
	 * Encrypts data using the public key
	 *
	 * @param data - The data to encrypt
	 * @param label - Optional label for OAEP (additional authenticated data)
	 * @returns The encrypted data as an ArrayBuffer
	 */
	async encrypt(data: string | BufferSource, label?: BufferSource): Promise<ArrayBuffer> {
		const params: RsaOaepParams = { name: Krypton.Algorithm.RSA_OAEP };
		if (label) { params.label = label }

		return await Krypton.encrypt(params, this.publicKey, data);
	}

	/**
	 * Decrypts data using the private key
	 *
	 * @param data - The data to decrypt
	 * @param label - Optional label for OAEP (must match the label used during encryption)
	 * @returns The decrypted data as a string
	 */
	async decrypt(data: BufferSource, label?: BufferSource): Promise<string> {
		const params: RsaOaepParams = { name: Krypton.Algorithm.RSA_OAEP };
		if (label) { params.label = label }

		return await Krypton.decrypt(params, this.privateKey, data);
	}
}
