import { Krypton } from '../krypton.js';
import type { EcdsaHashAlgorithm, EcdsaNamedCurve, SigningCipher } from '../types.js';

/**
 * ECDSA cipher for the Web Crypto API.
 * Provides digital signatures using elliptic curve cryptography (sign/verify).
 *
 * Create instances via {@link Krypton.create}.
 *
 * @author D1g1talEntr0py <jason.dimeo@gmail.com>
 */
export class EcdsaCipher implements SigningCipher {
	private readonly publicKey: CryptoKey;
	private readonly privateKey: CryptoKey;
	private readonly hash: EcdsaHashAlgorithm;

	/**
	 * @param publicKey - The public key for verification
	 * @param privateKey - The private key for signing
	 * @param hash - The hash algorithm to use
	 */
	private constructor(publicKey: CryptoKey, privateKey: CryptoKey, hash: EcdsaHashAlgorithm) {
		this.publicKey = publicKey;
		this.privateKey = privateKey;
		this.hash = hash;
	}

	/**
	 * Creates a new EcdsaCipher instance
	 *
	 * @param options - Optional configuration including existing keys, curve, or hash algorithm
	 * @returns A promise that resolves to a new EcdsaCipher instance
	 */
	static async create(options?: { keyPair?: CryptoKeyPair; namedCurve?: EcdsaNamedCurve; hash?: EcdsaHashAlgorithm }): Promise<EcdsaCipher> {
		const hash = options?.hash ?? Krypton.Hash.SHA_256;

		if (options?.keyPair) {
			return new EcdsaCipher(options.keyPair.publicKey, options.keyPair.privateKey, hash);
		}

		const keyPair = await Krypton.generateKey(Krypton.Algorithm.ECDSA, { usages: ['sign', 'verify'] }) as CryptoKeyPair;

		return new EcdsaCipher(keyPair.publicKey, keyPair.privateKey, hash);
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
	 * Signs data using the private key
	 *
	 * @param data - The data to sign
	 * @returns The signature as an ArrayBuffer
	 */
	async sign(data: string | BufferSource): Promise<ArrayBuffer> {
		return await Krypton.sign({ name: Krypton.Algorithm.ECDSA, hash: this.hash }, this.privateKey, data);
	}

	/**
	 * Verifies a signature against data using the public key
	 *
	 * @param signature - The signature to verify
	 * @param data - The data that was signed
	 * @returns true if the signature is valid
	 */
	async verify(signature: BufferSource, data: string | BufferSource): Promise<boolean> {
		return await Krypton.verify({ name: Krypton.Algorithm.ECDSA, hash: this.hash }, this.publicKey, signature, data);
	}
}
