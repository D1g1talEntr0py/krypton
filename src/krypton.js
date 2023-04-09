/**
 * Krypton is a simple wrapper around the Web Crypto API
 *
 * @module {Krypton} krypton
 * @author D1g1talEntr0py <jason.dimeo@gmail.com>
 */
export default class Krypton {
	/** @type {string} */
	#algorithm;
	/** @type {Promise<CryptoKey|CryptoKeyPair>} */
	#key;
	/** @type {RsaOaepParams|AesCbcParams|AesCtrParams|AesGcmParams} */
	#parameters;
	/** @type {TextEncoder} */
	static #textEncoder = new TextEncoder();
	/** @type {TextDecoder} */
	static #textDecoder = new TextDecoder();

	/**
	 *
	 * @param {string} [algorithm='AES-GCM'] - The algorithm to use
	 * @param {CryptoKey|CryptoKeyPair} [key] - The key to use
	 */
	constructor(algorithm = Krypton.Algorithm.AES_GCM, key) {
		if (!Object.values(Krypton.Algorithm, algorithm)) throw new Error(`Unsupported algorithm: ${algorithm}`);
		this.#algorithm = algorithm;
		this.#key = key ? Promise.resolve(key) : Krypton.generateKey(algorithm);
		this.#parameters = Krypton.#generateParameters(algorithm);
	}

	/** @constant {Object<string, string>} */
	static Algorithm = {
		AES_CBC: 'AES-CBC',
		AES_CTR: 'AES-CTR',
		AES_GCM: 'AES-GCM',
		RSA_OAEP: 'RSA-OAEP'
	};

	/** @constant {Object<string, string>} */
	static Hash = {
		SHA_1: 'SHA-1',
		SHA_256: 'SHA-256',
		SHA_384: 'SHA-384',
		SHA_512: 'SHA-512'
	};

	/**
	 * Generates a key using the algorithm specified when the Krypton object was created
	 *
	 * @async
	 * @param {string} [algorithm='AES-GCM'] - The algorithm to use
	 * @returns {Promise<CryptoKey>} The generated key
	 * @throws {Error} If the algorithm is not supported or some other error occurs
	 */
	static async generateKey(algorithm = Krypton.Algorithm.AES_GCM) {
		return await globalThis.crypto.subtle.generateKey(Krypton.#generateKeyParameters(algorithm), false, ['encrypt', 'decrypt']);
	}

	/**
	 * Encrypts the data using the algorithm specified when the Krypton object was created
	 *
	 * @param {*} data - The data to encrypt
	 * @param {CryptoKey|CryptoKeyPair} [key=this.#key] - The key to use
	 * @returns {Promise<ArrayBuffer>} The encrypted data as an {@link ArrayBuffer}
	 * @throws {Error} If the algorithm is not supported or some other error occurs
	 */
	async encrypt(data, key) {
		key ??= await this.#key;
		return await globalThis.crypto.subtle.encrypt(this.#parameters, key?.publicKey ?? key, Krypton.#textEncoder.encode(data));
	}

	/**
	 * Decrypts the data using the algorithm specified when the Krypton object was created
	 *
	 * @param {ArrayBuffer} data - The data to decrypt
	 * @param {CryptoKey|CryptoKeyPair} [key=this.#key] - The key to use
	 * @returns {Promise<string>} The decrypted data as a string
	 * @throws {Error} If the algorithm is not supported or some other error occurs
	 */
	async decrypt(data, key) {
		key ??= await this.#key;
		return Krypton.#textDecoder.decode(await globalThis.crypto.subtle.decrypt(this.#parameters, key?.privateKey ?? key, data));
	}

	/**
	 * Generates random values using the Web Crypto API
	 *
	 * @private
	 * @static
	 * @param {number} [size=256] - The number of bits to generate
	 * @returns {Uint8Array} The generated random values
	 * @throws {Error} If the algorithm is not supported or some other error occurs
	 * @see {@link https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues}
	 */
	static #randomValues(size = 256) {
		return globalThis.crypto.getRandomValues(new Uint8Array(size / 8));
	}

	/**
	 * Generates the parameters for the key generation
	 *
	 * @private
	 * @param {string} algorithm - The algorithm to use
	 * @returns {AesKeyGenParams|RsaKeyGenParams} The parameters for the key generation
	 * @throws {Error} If the algorithm is not supported
	 */
	static #generateKeyParameters(algorithm) {
		switch (algorithm) {
			case Krypton.Algorithm.AES_CTR:
			case Krypton.Algorithm.AES_CBC:
			case Krypton.Algorithm.AES_GCM:	return { name: algorithm, length: 256 };
			case Krypton.Algorithm.RSA_OAEP: return { name: algorithm, modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]), hash: Krypton.Hash.SHA_512 };
			default: throw new Error(`Unsupported algorithm ${algorithm}`);
		}
	}

	/**
	 * Generates the parameters for the encryption/decryption
	 *
	 * @private
	 * @param {string} algorithm - The algorithm to use
	 * @returns {AesCtrParams|AesCbcParams|AesGcmParams|RsaOaepParams} The parameters for the encryption/decryption
	 * @throws {Error} If the algorithm is not supported
	 */
	static #generateParameters(algorithm) {
		switch (algorithm) {
			case Krypton.Algorithm.AES_CTR: return { name: algorithm, counter: Krypton.#randomValues(128), length: 64 };
			case Krypton.Algorithm.AES_CBC: return { name: algorithm, iv: Krypton.#randomValues(128) };
			case Krypton.Algorithm.AES_GCM: return { name: algorithm, iv: Krypton.#randomValues(96), additionalData: undefined, tagLength: 128 };
			case Krypton.Algorithm.RSA_OAEP: return { name: algorithm, label: undefined };
			default: throw new Error(`Unsupported algorithm ${algorithm}`);
		}
	}
}