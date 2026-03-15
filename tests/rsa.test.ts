import { describe, it, expect } from 'vitest';
import { Krypton } from '../src/krypton.js';
import { RsaCipher } from '../src/ciphers/rsa.js';

describe('RsaCipher', () => {
	describe('create', () => {
		it('should create an RSA-OAEP cipher via Krypton.create', async () => {
			const rsa = await Krypton.create('RSA-OAEP');
			expect(rsa).toBeInstanceOf(RsaCipher);
		});

		it('should create from an existing key pair', async () => {
			const keyPair = await Krypton.generateKey(Krypton.Algorithm.RSA_OAEP) as CryptoKeyPair;
			const rsa = await RsaCipher.create({ keyPair });
			expect(rsa).toBeInstanceOf(RsaCipher);
		});

		it('should create from separate public and private keys', async () => {
			const keyPair = await Krypton.generateKey(Krypton.Algorithm.RSA_OAEP) as CryptoKeyPair;
			const rsa = await RsaCipher.create({ publicKey: keyPair.publicKey, privateKey: keyPair.privateKey });
			expect(rsa).toBeInstanceOf(RsaCipher);
		});
	});

	describe('encrypt / decrypt', () => {
		it('should encrypt and decrypt a string', async () => {
			const rsa = await Krypton.create('RSA-OAEP');
			const data = 'Hello, RSA!';
			const encrypted = await rsa.encrypt(data);
			expect(encrypted).toBeInstanceOf(ArrayBuffer);
			const decrypted = await rsa.decrypt(encrypted);
			expect(decrypted).toEqual(data);
		});

		it('should encrypt and decrypt unicode and emoji', async () => {
			const rsa = await Krypton.create('RSA-OAEP');
			const data = '🔐 Secret RSA 鍵 🔑';
			const encrypted = await rsa.encrypt(data);
			const decrypted = await rsa.decrypt(encrypted);
			expect(decrypted).toEqual(data);
		});

		it('should encrypt and decrypt an empty string', async () => {
			const rsa = await Krypton.create('RSA-OAEP');
			const encrypted = await rsa.encrypt('');
			const decrypted = await rsa.decrypt(encrypted);
			expect(decrypted).toEqual('');
		});

		it('should produce different ciphertext for the same plaintext', async () => {
			const rsa = await Krypton.create('RSA-OAEP');
			const data = 'Same data';
			const encrypted1 = await rsa.encrypt(data);
			const encrypted2 = await rsa.encrypt(data);
			const e1 = new Uint8Array(encrypted1);
			const e2 = new Uint8Array(encrypted2);
			const areEqual = e1.length === e2.length && e1.every((v, i) => v === e2[i]);
			expect(areEqual).toBe(false);
		});

		it('should encrypt with label and decrypt with same label', async () => {
			const rsa = await Krypton.create('RSA-OAEP');
			const data = 'Labeled message';
			const label = Krypton.encode('my-label');
			const encrypted = await rsa.encrypt(data, label);
			const decrypted = await rsa.decrypt(encrypted, label);
			expect(decrypted).toEqual(data);
		});

		it('should fail to decrypt with wrong label', async () => {
			const rsa = await Krypton.create('RSA-OAEP');
			const data = 'Labeled message';
			const label = Krypton.encode('correct-label');
			const wrongLabel = Krypton.encode('wrong-label');
			const encrypted = await rsa.encrypt(data, label);
			await expect(rsa.decrypt(encrypted, wrongLabel)).rejects.toThrow();
		});
	});

	describe('key export', () => {
		it('should export public key as JWK', async () => {
			const rsa = await Krypton.create('RSA-OAEP');
			const jwk = await rsa.exportPublicKey();
			expect(jwk).toHaveProperty('kty', 'RSA');
			expect(jwk).toHaveProperty('key_ops');
		});

		it('should export private key as JWK', async () => {
			const rsa = await Krypton.create('RSA-OAEP');
			const jwk = await rsa.exportPrivateKey();
			expect(jwk).toHaveProperty('kty', 'RSA');
			expect(jwk).toHaveProperty('d'); // private exponent
		});

		it('should export public key in SPKI format', async () => {
			const rsa = await Krypton.create('RSA-OAEP');
			const spki = await rsa.exportPublicKey('spki');
			expect(spki).toBeInstanceOf(ArrayBuffer);
		});

		it('should export private key in PKCS8 format', async () => {
			const rsa = await Krypton.create('RSA-OAEP');
			const pkcs8 = await rsa.exportPrivateKey('pkcs8');
			expect(pkcs8).toBeInstanceOf(ArrayBuffer);
		});
	});
});
