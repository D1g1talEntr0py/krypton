import { describe, it, expect } from 'vitest';
import { Krypton } from '../src/krypton.js';
import { AesCipher } from '../src/ciphers/aes.js';

describe('Krypton', () => {
	describe('encode / decode', () => {
		it('should round-trip a basic string', () => {
			const data = 'Hello, World!';
			const encoded = Krypton.encode(data);
			const decoded = Krypton.decode(encoded);
			expect(decoded).toEqual(data);
		});

		it('should handle an empty string', () => {
			const encoded = Krypton.encode('');
			expect(encoded.byteLength).toBe(0);
			expect(Krypton.decode(encoded)).toEqual('');
		});

		it('should handle unicode and emoji', () => {
			const data = '日本語テスト 🔐🔑✨';
			const encoded = Krypton.encode(data);
			expect(Krypton.decode(encoded)).toEqual(data);
		});
	});

	describe('randomUUID', () => {
		it('should return a valid UUID v4 format', () => {
			const uuid = Krypton.randomUUID();
			expect(uuid).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
		});

		it('should generate unique UUIDs', () => {
			const uuid1 = Krypton.randomUUID();
			const uuid2 = Krypton.randomUUID();
			expect(uuid1).not.toEqual(uuid2);
		});
	});

	describe('randomValues', () => {
		it('should generate 128-bit values by default', () => {
			const values = Krypton.randomValues();
			expect(values.byteLength).toBe(16); // 128 bits = 16 bytes
		});

		it('should generate Uint32Array for 32-divisible sizes', () => {
			const values = Krypton.randomValues(256);
			expect(values).toBeInstanceOf(Uint32Array);
			expect(values.byteLength).toBe(32);
		});

		it('should generate Uint16Array for 16-divisible (non-32) sizes', () => {
			const values = Krypton.randomValues(48);
			expect(values).toBeInstanceOf(Uint16Array);
			expect(values.byteLength).toBe(6);
		});

		it('should generate Uint8Array for 8-divisible sizes', () => {
			const values = Krypton.randomValues(8);
			expect(values).toBeInstanceOf(Uint8Array);
			expect(values.byteLength).toBe(1);
		});

		it('should generate 96-bit values for GCM IV', () => {
			const values = Krypton.randomValues(96);
			expect(values.byteLength).toBe(12);
		});

		it('should throw for invalid sizes', () => {
			expect(() => Krypton.randomValues(7)).toThrow('Invalid size');
		});
	});

	describe('generateKey', () => {
		it('should generate an AES-GCM key by default', async () => {
			const key = await Krypton.generateKey();
			expect(key).toBeDefined();
			expect((key as CryptoKey).algorithm.name).toBe('AES-GCM');
		});

		it('should generate an AES-CBC key', async () => {
			const key = await Krypton.generateKey(Krypton.Algorithm.AES_CBC);
			expect((key as CryptoKey).algorithm.name).toBe('AES-CBC');
		});

		it('should generate an AES-CTR key', async () => {
			const key = await Krypton.generateKey(Krypton.Algorithm.AES_CTR);
			expect((key as CryptoKey).algorithm.name).toBe('AES-CTR');
		});

		it('should generate an RSA-OAEP key pair', async () => {
			const keyPair = await Krypton.generateKey(Krypton.Algorithm.RSA_OAEP);
			expect((keyPair as CryptoKeyPair).publicKey).toBeDefined();
			expect((keyPair as CryptoKeyPair).privateKey).toBeDefined();
		});

		it('should generate an HMAC key', async () => {
			const key = await Krypton.generateKey(Krypton.Algorithm.HMAC, { usages: ['sign', 'verify'] });
			expect((key as CryptoKey).algorithm.name).toBe('HMAC');
		});

		it('should respect extractable option', async () => {
			const key = await Krypton.generateKey(Krypton.Algorithm.AES_GCM, { extractable: false }) as CryptoKey;
			expect(key.extractable).toBe(false);
		});

		it('should throw for unsupported algorithm', async () => {
			await expect(Krypton.generateKey('INVALID')).rejects.toThrow('Unsupported algorithm');
		});
	});

	describe('exportKey / importKey', () => {
		it('should round-trip a key in JWK format', async () => {
			const key = await Krypton.generateKey() as CryptoKey;
			const exported = await Krypton.exportKey(key, 'jwk');
			expect(exported).toHaveProperty('kty');
			const imported = await Krypton.importKey(exported);
			expect(imported.algorithm.name).toBe('AES-GCM');
		});

		it('should round-trip a key in RAW format', async () => {
			const key = await Krypton.generateKey() as CryptoKey;
			const exported = await Krypton.exportKey(key, 'raw');
			expect(exported).toBeInstanceOf(ArrayBuffer);
			expect(exported.byteLength).toBe(32); // 256-bit key
			const imported = await Krypton.importKey(exported, Krypton.Algorithm.AES_GCM, Krypton.KeyFormat.RAW);
			expect(imported.algorithm.name).toBe('AES-GCM');
		});

		it('should encrypt with original key and decrypt with imported key', async () => {
			const key = await Krypton.generateKey() as CryptoKey;
			const exported = await Krypton.exportKey(key, 'jwk');
			const imported = await Krypton.importKey(exported);

			const data = 'Secret message';
			const params = Krypton.generateParameters();
			const encrypted = await Krypton.encrypt(params, key, data);
			const decrypted = await Krypton.decrypt(params, imported, encrypted);
			expect(decrypted).toEqual(data);
		});
	});

	describe('encrypt / decrypt', () => {
		it('should encrypt and decrypt a string using defaults', async () => {
			const data = 'Hello, World!';
			const key = await Krypton.generateKey() as CryptoKey;
			const parameters = Krypton.generateParameters();
			const encrypted = await Krypton.encrypt(parameters, key, data);
			const decrypted = await Krypton.decrypt(parameters, key, encrypted);
			expect(decrypted).toEqual(data);
		});

		it('should encrypt and decrypt using AES-CBC', async () => {
			const data = 'Hello, World!';
			const key = await Krypton.generateKey(Krypton.Algorithm.AES_CBC) as CryptoKey;
			const parameters = Krypton.generateParameters(Krypton.Algorithm.AES_CBC);
			const encrypted = await Krypton.encrypt(parameters, key, data);
			const decrypted = await Krypton.decrypt(parameters, key, encrypted);
			expect(decrypted).toEqual(data);
		});

		it('should encrypt and decrypt using AES-CTR', async () => {
			const data = 'Hello, World!';
			const key = await Krypton.generateKey(Krypton.Algorithm.AES_CTR) as CryptoKey;
			const parameters = Krypton.generateParameters(Krypton.Algorithm.AES_CTR);
			const encrypted = await Krypton.encrypt(parameters, key, data);
			const decrypted = await Krypton.decrypt(parameters, key, encrypted);
			expect(decrypted).toEqual(data);
		});

		it('should produce different ciphertext with different IVs', async () => {
			const data = 'Same data';
			const key = await Krypton.generateKey() as CryptoKey;
			const params1 = Krypton.generateParameters();
			const params2 = Krypton.generateParameters();
			const encrypted1 = await Krypton.encrypt(params1, key, data);
			const encrypted2 = await Krypton.encrypt(params2, key, data);

			const e1 = new Uint8Array(encrypted1);
			const e2 = new Uint8Array(encrypted2);
			const areEqual = e1.length === e2.length && e1.every((v, i) => v === e2[i]);
			expect(areEqual).toBe(false);
		});

		it('should accept BufferSource as input', async () => {
			const data = 'Hello, World!';
			const key = await Krypton.generateKey() as CryptoKey;
			const params = Krypton.generateParameters();
			const encoded = Krypton.encode(data);
			const encrypted = await Krypton.encrypt(params, key, encoded);
			const decrypted = await Krypton.decrypt(params, key, encrypted);
			expect(decrypted).toEqual(data);
		});

		it('should encrypt and decrypt an empty string', async () => {
			const key = await Krypton.generateKey() as CryptoKey;
			const params = Krypton.generateParameters();
			const encrypted = await Krypton.encrypt(params, key, '');
			const decrypted = await Krypton.decrypt(params, key, encrypted);
			expect(decrypted).toEqual('');
		});

		it('should encrypt and decrypt unicode / emoji', async () => {
			const data = '🔐 Héllo Wörld! 日本語 🔑';
			const key = await Krypton.generateKey() as CryptoKey;
			const params = Krypton.generateParameters();
			const encrypted = await Krypton.encrypt(params, key, data);
			const decrypted = await Krypton.decrypt(params, key, encrypted);
			expect(decrypted).toEqual(data);
		});

		it('should encrypt and decrypt large data', async () => {
			const data = 'A'.repeat(1024 * 1024); // 1MB
			const key = await Krypton.generateKey() as CryptoKey;
			const params = Krypton.generateParameters();
			const encrypted = await Krypton.encrypt(params, key, data);
			const decrypted = await Krypton.decrypt(params, key, encrypted);
			expect(decrypted).toEqual(data);
		});
	});

	describe('RSA-OAEP', () => {
		it('should encrypt with public key and decrypt with private key', async () => {
			const keyPair = await Krypton.generateKey(Krypton.Algorithm.RSA_OAEP) as CryptoKeyPair;
			const params = Krypton.generateParameters(Krypton.Algorithm.RSA_OAEP);
			const data = 'RSA encrypted message';
			const encrypted = await Krypton.encrypt(params, keyPair.publicKey, data);
			const decrypted = await Krypton.decrypt(params, keyPair.privateKey, encrypted);
			expect(decrypted).toEqual(data);
		});

		it('should generate correct parameters for RSA-OAEP', () => {
			const params = Krypton.generateParameters(Krypton.Algorithm.RSA_OAEP);
			expect(params.name).toBe('RSA-OAEP');
		});
	});

	describe('generateParameters', () => {
		it('should generate AES-GCM parameters by default', () => {
			const params = Krypton.generateParameters() as AesGcmParams;
			expect(params.name).toBe('AES-GCM');
			expect(params.iv).toBeDefined();
			expect(params.tagLength).toBe(128);
		});

		it('should generate AES-CBC parameters', () => {
			const params = Krypton.generateParameters(Krypton.Algorithm.AES_CBC) as AesCbcParams;
			expect(params.name).toBe('AES-CBC');
			expect(params.iv).toBeDefined();
		});

		it('should generate AES-CTR parameters with length 128', () => {
			const params = Krypton.generateParameters(Krypton.Algorithm.AES_CTR) as AesCtrParams;
			expect(params.name).toBe('AES-CTR');
			expect(params.counter).toBeDefined();
			expect(params.length).toBe(128);
		});

		it('should include additionalData for AES-GCM when provided', () => {
			const aad = Krypton.encode('additional data');
			const params = Krypton.generateParameters(Krypton.Algorithm.AES_GCM, { additionalData: aad }) as AesGcmParams;
			expect(params.additionalData).toBeDefined();
		});

		it('should throw for unsupported algorithm', () => {
			expect(() => Krypton.generateParameters('INVALID')).toThrow('Unsupported algorithm');
		});
	});

	describe('digest', () => {
		it('should compute a SHA-256 hash', async () => {
			const hash = await Krypton.digest(Krypton.Hash.SHA_256, 'hello');
			expect(hash).toBeInstanceOf(ArrayBuffer);
			expect(hash.byteLength).toBe(32); // 256 bits
		});

		it('should compute a SHA-512 hash', async () => {
			const hash = await Krypton.digest(Krypton.Hash.SHA_512, 'hello');
			expect(hash.byteLength).toBe(64); // 512 bits
		});

		it('should produce consistent hashes for same input', async () => {
			const hash1 = await Krypton.digest(Krypton.Hash.SHA_256, 'test');
			const hash2 = await Krypton.digest(Krypton.Hash.SHA_256, 'test');
			const h1 = new Uint8Array(hash1);
			const h2 = new Uint8Array(hash2);
			expect(h1).toEqual(h2);
		});

		it('should produce different hashes for different input', async () => {
			const hash1 = await Krypton.digest(Krypton.Hash.SHA_256, 'hello');
			const hash2 = await Krypton.digest(Krypton.Hash.SHA_256, 'world');
			const h1 = new Uint8Array(hash1);
			const h2 = new Uint8Array(hash2);
			expect(h1).not.toEqual(h2);
		});

		it('should accept BufferSource as input', async () => {
			const data = Krypton.encode('hello');
			const hash1 = await Krypton.digest(Krypton.Hash.SHA_256, data);
			const hash2 = await Krypton.digest(Krypton.Hash.SHA_256, 'hello');
			const h1 = new Uint8Array(hash1);
			const h2 = new Uint8Array(hash2);
			expect(h1).toEqual(h2);
		});
	});

	describe('sign / verify', () => {
		it('should sign and verify with HMAC', async () => {
			const key = await Krypton.generateKey(Krypton.Algorithm.HMAC, { usages: ['sign', 'verify'] }) as CryptoKey;
			const data = 'Hello, World!';
			const signature = await Krypton.sign(Krypton.Algorithm.HMAC, key, data);
			expect(signature).toBeInstanceOf(ArrayBuffer);
			const isValid = await Krypton.verify(Krypton.Algorithm.HMAC, key, signature, data);
			expect(isValid).toBe(true);
		});

		it('should reject invalid signatures', async () => {
			const key = await Krypton.generateKey(Krypton.Algorithm.HMAC, { usages: ['sign', 'verify'] }) as CryptoKey;
			const signature = await Krypton.sign(Krypton.Algorithm.HMAC, key, 'original data');
			const isValid = await Krypton.verify(Krypton.Algorithm.HMAC, key, signature, 'tampered data');
			expect(isValid).toBe(false);
		});

		it('should sign and verify with BufferSource data', async () => {
			const key = await Krypton.generateKey(Krypton.Algorithm.HMAC, { usages: ['sign', 'verify'] }) as CryptoKey;
			const data = Krypton.encode('Hello, World!');
			const signature = await Krypton.sign(Krypton.Algorithm.HMAC, key, data);
			const isValid = await Krypton.verify(Krypton.Algorithm.HMAC, key, signature, data);
			expect(isValid).toBe(true);
		});
	});

	describe('deriveKey / importKeyMaterial', () => {
		it('should derive a key from a password using PBKDF2', async () => {
			const baseKey = await Krypton.importKeyMaterial('my-password');
			const salt = Krypton.randomValues(128);
			const derivedKey = await Krypton.deriveKey(
				{ name: Krypton.Algorithm.PBKDF2, salt, iterations: 100000, hash: Krypton.Hash.SHA_256 },
				baseKey,
				{ name: Krypton.Algorithm.AES_GCM, length: 256 }
			);
			expect(derivedKey).toBeDefined();
			expect(derivedKey.algorithm.name).toBe('AES-GCM');
		});

		it('should produce consistent keys from same password and salt', async () => {
			const salt = Krypton.randomValues(128);
			const params = { name: Krypton.Algorithm.PBKDF2, salt, iterations: 100000, hash: Krypton.Hash.SHA_256 };
			const derivedAlgo = { name: Krypton.Algorithm.AES_GCM, length: 256 } as const;

			const baseKey1 = await Krypton.importKeyMaterial('same-password');
			const key1 = await Krypton.deriveKey(params, baseKey1, derivedAlgo, { extractable: true });
			const exported1 = await Krypton.exportKey(key1, 'raw');

			const baseKey2 = await Krypton.importKeyMaterial('same-password');
			const key2 = await Krypton.deriveKey(params, baseKey2, derivedAlgo, { extractable: true });
			const exported2 = await Krypton.exportKey(key2, 'raw');

			expect(new Uint8Array(exported1)).toEqual(new Uint8Array(exported2));
		});

		it('should derive a key using HKDF', async () => {
			const baseKey = await Krypton.importKeyMaterial('key-material', Krypton.Algorithm.HKDF);
			const salt = Krypton.randomValues(128);
			const info = Krypton.encode('app context');
			const derivedKey = await Krypton.deriveKey(
				{ name: Krypton.Algorithm.HKDF, salt, info, hash: Krypton.Hash.SHA_256 },
				baseKey,
				{ name: Krypton.Algorithm.AES_GCM, length: 256 }
			);
			expect(derivedKey.algorithm.name).toBe('AES-GCM');
		});

		it('should use a PBKDF2-derived key for encryption/decryption', async () => {
			const baseKey = await Krypton.importKeyMaterial('my-password');
			const salt = Krypton.randomValues(128);
			const derivedKey = await Krypton.deriveKey(
				{ name: Krypton.Algorithm.PBKDF2, salt, iterations: 100000, hash: Krypton.Hash.SHA_256 },
				baseKey,
				{ name: Krypton.Algorithm.AES_GCM, length: 256 }
			);

			const data = 'Secret data encrypted with derived key';
			const params = Krypton.generateParameters();
			const encrypted = await Krypton.encrypt(params, derivedKey, data);
			const decrypted = await Krypton.decrypt(params, derivedKey, encrypted);
			expect(decrypted).toEqual(data);
		});
	});

	describe('wrapKey / unwrapKey', () => {
		it('should wrap and unwrap a key', async () => {
			const keyToWrap = await Krypton.generateKey() as CryptoKey;
			const wrappingKey = await Krypton.generateKey(Krypton.Algorithm.AES_GCM, { usages: ['wrapKey', 'unwrapKey'] }) as CryptoKey;
			const wrapParams = Krypton.generateParameters();

			const wrappedKey = await Krypton.wrapKey('raw', keyToWrap, wrappingKey, wrapParams);
			expect(wrappedKey).toBeInstanceOf(ArrayBuffer);

			const unwrappedKey = await Krypton.unwrapKey('raw', wrappedKey, wrappingKey, wrapParams, { name: 'AES-GCM', length: 256 });
			expect(unwrappedKey.algorithm.name).toBe('AES-GCM');

			// Verify the unwrapped key works for encryption
			const data = 'test';
			const params = Krypton.generateParameters();
			const encrypted = await Krypton.encrypt(params, unwrappedKey, data);
			const decrypted = await Krypton.decrypt(params, unwrappedKey, encrypted);
			expect(decrypted).toEqual(data);
		});
	});

	describe('static constants', () => {
		it('should have Algorithm constants', () => {
			expect(Krypton.Algorithm.AES_CBC).toBe('AES-CBC');
			expect(Krypton.Algorithm.AES_CTR).toBe('AES-CTR');
			expect(Krypton.Algorithm.AES_GCM).toBe('AES-GCM');
			expect(Krypton.Algorithm.RSA_OAEP).toBe('RSA-OAEP');
			expect(Krypton.Algorithm.HMAC).toBe('HMAC');
			expect(Krypton.Algorithm.ECDSA).toBe('ECDSA');
			expect(Krypton.Algorithm.PBKDF2).toBe('PBKDF2');
			expect(Krypton.Algorithm.HKDF).toBe('HKDF');
		});

		it('should have Hash constants', () => {
			expect(Krypton.Hash.SHA_1).toBe('SHA-1');
			expect(Krypton.Hash.SHA_256).toBe('SHA-256');
			expect(Krypton.Hash.SHA_384).toBe('SHA-384');
			expect(Krypton.Hash.SHA_512).toBe('SHA-512');
		});

		it('should have KeyFormat constants', () => {
			expect(Krypton.KeyFormat.JWK).toBe('jwk');
			expect(Krypton.KeyFormat.RAW).toBe('raw');
			expect(Krypton.KeyFormat.SPKI).toBe('spki');
			expect(Krypton.KeyFormat.PKCS8).toBe('pkcs8');
		});
	});
});

describe('Krypton.create (AES)', () => {
	describe('create', () => {
		it('should create an AES-GCM cipher', async () => {
			const aes = await Krypton.create('AES-GCM');
			expect(aes).toBeInstanceOf(AesCipher);
		});
	});

	describe('encrypt / decrypt', () => {
		it('should encrypt and decrypt using AES-GCM', async () => {
			const data = 'Hello, World!';
			const aes = await Krypton.create('AES-GCM');
			const encrypted = await aes.encrypt(data);
			const decrypted = await aes.decrypt(encrypted);
			expect(encrypted).toBeInstanceOf(ArrayBuffer);
			expect(decrypted).toEqual(data);
		});

		it('should encrypt and decrypt using AES-CBC', async () => {
			const data = 'Hello, World!';
			const aes = await Krypton.create('AES-CBC');
			const encrypted = await aes.encrypt(data);
			const decrypted = await aes.decrypt(encrypted);
			expect(encrypted).toBeInstanceOf(ArrayBuffer);
			expect(decrypted).toEqual(data);
		});

		it('should encrypt and decrypt using AES-CTR', async () => {
			const data = 'Hello, World!';
			const aes = await Krypton.create('AES-CTR');
			const encrypted = await aes.encrypt(data);
			const decrypted = await aes.decrypt(encrypted);
			expect(encrypted).toBeInstanceOf(ArrayBuffer);
			expect(decrypted).toEqual(data);
		});
	});

	describe('IV uniqueness (security)', () => {
		it('should produce different ciphertext for same data (fresh IV per encrypt)', async () => {
			const aes = await Krypton.create('AES-GCM');
			const data = 'Same data encrypted twice';
			const encrypted1 = await aes.encrypt(data);
			const encrypted2 = await aes.encrypt(data);

			const e1 = new Uint8Array(encrypted1);
			const e2 = new Uint8Array(encrypted2);
			const areEqual = e1.length === e2.length && e1.every((v, i) => v === e2[i]);
			expect(areEqual).toBe(false);
		});

		it('should prepend IV to ciphertext (GCM: 12-byte IV)', async () => {
			const aes = await Krypton.create('AES-GCM');
			const encrypted = await aes.encrypt('test');
			// GCM IV is 12 bytes, ciphertext includes 16-byte auth tag + encrypted data
			const bytes = new Uint8Array(encrypted);
			expect(bytes.byteLength).toBeGreaterThan(12);
		});

		it('should prepend IV to ciphertext (CBC: 16-byte IV)', async () => {
			const aes = await Krypton.create('AES-CBC');
			const encrypted = await aes.encrypt('test');
			const bytes = new Uint8Array(encrypted);
			expect(bytes.byteLength).toBeGreaterThan(16);
		});

		it('should prepend counter to ciphertext (CTR: 16-byte counter)', async () => {
			const aes = await Krypton.create('AES-CTR');
			const encrypted = await aes.encrypt('test');
			const bytes = new Uint8Array(encrypted);
			expect(bytes.byteLength).toBeGreaterThan(16);
		});
	});

	describe('key import / export', () => {
		it('should create a cipher from an existing CryptoKey', async () => {
			const key = await Krypton.generateKey(Krypton.Algorithm.AES_GCM) as CryptoKey;
			const aes = await Krypton.create('AES-GCM', { key });
			const data = 'Hello from imported key';
			const encrypted = await aes.encrypt(data);
			const decrypted = await aes.decrypt(encrypted);
			expect(decrypted).toEqual(data);
		});

		it('should create a cipher from a JsonWebKey', async () => {
			const key = await Krypton.generateKey(Krypton.Algorithm.AES_GCM) as CryptoKey;
			const jwk = await Krypton.exportKey(key, 'jwk');
			const aes = await Krypton.create('AES-GCM', { key: jwk });
			const data = 'Hello from JWK';
			const encrypted = await aes.encrypt(data);
			const decrypted = await aes.decrypt(encrypted);
			expect(decrypted).toEqual(data);
		});

		it('should export and reimport a key', async () => {
			const aes1 = await Krypton.create('AES-GCM');
			const data = 'Cross-instance encryption';
			const encrypted = await aes1.encrypt(data);

			const exportedKey = await aes1.exportKey();
			const aes2 = await Krypton.create('AES-GCM', { key: exportedKey as JsonWebKey });
			const decrypted = await aes2.decrypt(encrypted);
			expect(decrypted).toEqual(data);
		});
	});

	describe('edge cases', () => {
		it('should encrypt and decrypt an empty string', async () => {
			const aes = await Krypton.create('AES-GCM');
			const encrypted = await aes.encrypt('');
			const decrypted = await aes.decrypt(encrypted);
			expect(decrypted).toEqual('');
		});

		it('should encrypt and decrypt unicode and emoji', async () => {
			const aes = await Krypton.create('AES-GCM');
			const data = '🔑 Schlüssel 暗号化 🔐';
			const encrypted = await aes.encrypt(data);
			const decrypted = await aes.decrypt(encrypted);
			expect(decrypted).toEqual(data);
		});

		it('should encrypt and decrypt large data', async () => {
			const aes = await Krypton.create('AES-GCM');
			const data = 'X'.repeat(100000);
			const encrypted = await aes.encrypt(data);
			const decrypted = await aes.decrypt(encrypted);
			expect(decrypted).toEqual(data);
		});
	});

	describe('AAD (Additional Authenticated Data)', () => {
		it('should encrypt and decrypt with AAD', async () => {
			const aes = await Krypton.create('AES-GCM');
			const data = 'Secret message';
			const aad = Krypton.encode('authenticated header');
			const encrypted = await aes.encrypt(data, aad);
			const decrypted = await aes.decrypt(encrypted, aad);
			expect(decrypted).toEqual(data);
		});

		it('should fail to decrypt with wrong AAD', async () => {
			const aes = await Krypton.create('AES-GCM');
			const data = 'Secret message';
			const aad = Krypton.encode('correct header');
			const wrongAad = Krypton.encode('wrong header');
			const encrypted = await aes.encrypt(data, aad);
			await expect(aes.decrypt(encrypted, wrongAad)).rejects.toThrow();
		});
	});
});