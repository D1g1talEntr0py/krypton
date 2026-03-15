import { Krypton } from '../krypton.js';
import type { EcdhNamedCurve } from '../types.js';

/**
 * ECDH cipher for the Web Crypto API.
 * Provides elliptic curve Diffie-Hellman key agreement for deriving shared secrets.
 *
 * Create instances via {@link Krypton.create}.
 *
 * @author D1g1talEntr0py <jason.dimeo@gmail.com>
 */
export class EcdhCipher {
	private readonly publicKey: CryptoKey;
	private readonly privateKey: CryptoKey;

	/**
	 * @param publicKey - The public key to share with the other party
	 * @param privateKey - The private key used for key derivation
	 */
	private constructor(publicKey: CryptoKey, privateKey: CryptoKey) {
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}

	/**
	 * Creates a new EcdhCipher instance
	 *
	 * @param options - Optional configuration including existing keys or named curve
	 * @returns A promise that resolves to a new EcdhCipher instance
	 */
	static async create(options?: { keyPair?: CryptoKeyPair; namedCurve?: EcdhNamedCurve }): Promise<EcdhCipher> {
		if (options?.keyPair) {
			return new EcdhCipher(options.keyPair.publicKey, options.keyPair.privateKey);
		}

		const namedCurve = options?.namedCurve ?? 'P-256';
		const keyPair = await crypto.subtle.generateKey({ name: Krypton.Algorithm.ECDH, namedCurve }, true, ['deriveKey', 'deriveBits']);

		return new EcdhCipher(keyPair.publicKey, keyPair.privateKey);
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
	 * Derives a shared AES key using the other party's public key
	 *
	 * @param otherPartyPublicKey - The other party's public CryptoKey
	 * @param derivedKeyAlgorithm - The algorithm for the derived key (default: AES-GCM 256-bit)
	 * @param options - Additional options for the derived key
	 * @returns A promise that resolves to the derived CryptoKey
	 */
	async deriveKey(otherPartyPublicKey: CryptoKey, derivedKeyAlgorithm: AesKeyGenParams | HmacKeyGenParams = { name: Krypton.Algorithm.AES_GCM, length: 256 }, { extractable = true, usages = ['encrypt', 'decrypt'] as KeyUsage[] }: { extractable?: boolean; usages?: KeyUsage[] } = {}): Promise<CryptoKey> {
		return await crypto.subtle.deriveKey({ name: Krypton.Algorithm.ECDH, public: otherPartyPublicKey }, this.privateKey, derivedKeyAlgorithm, extractable, usages);
	}

	/**
	 * Derives raw bits from the shared secret using the other party's public key
	 *
	 * @param otherPartyPublicKey - The other party's public CryptoKey
	 * @param length - The number of bits to derive (default: 256)
	 * @returns A promise that resolves to the derived bits as an ArrayBuffer
	 */
	async deriveBits(otherPartyPublicKey: CryptoKey, length: number = 256): Promise<ArrayBuffer> {
		return await crypto.subtle.deriveBits({ name: Krypton.Algorithm.ECDH, public: otherPartyPublicKey }, this.privateKey, length);
	}
}
