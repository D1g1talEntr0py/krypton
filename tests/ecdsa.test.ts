import { describe, it, expect } from 'vitest';
import { Krypton } from '../src/krypton.js';
import { EcdsaCipher } from '../src/ciphers/ecdsa.js';

describe('EcdsaCipher', () => {
	describe('create', () => {
		it('should create an ECDSA cipher via Krypton.create', async () => {
			const ecdsa = await Krypton.create('ECDSA');
			expect(ecdsa).toBeInstanceOf(EcdsaCipher);
		});

		it('should create from an existing key pair', async () => {
			const keyPair = await Krypton.generateKey(Krypton.Algorithm.ECDSA, { usages: ['sign', 'verify'] }) as CryptoKeyPair;
			const ecdsa = await EcdsaCipher.create({ keyPair });
			expect(ecdsa).toBeInstanceOf(EcdsaCipher);
		});
	});

	describe('sign / verify', () => {
		it('should sign and verify a string', async () => {
			const ecdsa = await Krypton.create('ECDSA');
			const data = 'Hello, ECDSA!';
			const signature = await ecdsa.sign(data);
			expect(signature).toBeInstanceOf(ArrayBuffer);
			const isValid = await ecdsa.verify(signature, data);
			expect(isValid).toBe(true);
		});

		it('should reject tampered data', async () => {
			const ecdsa = await Krypton.create('ECDSA');
			const signature = await ecdsa.sign('original data');
			const isValid = await ecdsa.verify(signature, 'tampered data');
			expect(isValid).toBe(false);
		});

		it('should reject a tampered signature', async () => {
			const ecdsa = await Krypton.create('ECDSA');
			const data = 'test data';
			const signature = await ecdsa.sign(data);
			const tampered = new Uint8Array(signature);
			tampered[0] ^= 0xff;
			const isValid = await ecdsa.verify(tampered.buffer, data);
			expect(isValid).toBe(false);
		});

		it('should sign and verify BufferSource data', async () => {
			const ecdsa = await Krypton.create('ECDSA');
			const data = Krypton.encode('binary data');
			const signature = await ecdsa.sign(data);
			const isValid = await ecdsa.verify(signature, data);
			expect(isValid).toBe(true);
		});

		it('should sign and verify unicode and emoji', async () => {
			const ecdsa = await Krypton.create('ECDSA');
			const data = '🔑 署名 テスト 🔐';
			const signature = await ecdsa.sign(data);
			const isValid = await ecdsa.verify(signature, data);
			expect(isValid).toBe(true);
		});

		it('should produce different signatures for the same data (non-deterministic)', async () => {
			const ecdsa = await Krypton.create('ECDSA');
			const data = 'same data';
			const sig1 = await ecdsa.sign(data);
			const sig2 = await ecdsa.sign(data);
			const s1 = new Uint8Array(sig1);
			const s2 = new Uint8Array(sig2);
			// ECDSA signatures are non-deterministic (use random k value)
			const areEqual = s1.length === s2.length && s1.every((v, i) => v === s2[i]);
			expect(areEqual).toBe(false);
		});

		it('should verify with a different instance using exported keys', async () => {
			const ecdsa1 = await Krypton.create('ECDSA');
			const data = 'Cross-instance verification';
			const signature = await ecdsa1.sign(data);

			const publicKeyJwk = await ecdsa1.exportPublicKey();
			const privateKeyJwk = await ecdsa1.exportPrivateKey();

			const publicKey = await crypto.subtle.importKey('jwk', publicKeyJwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
			const privateKey = await crypto.subtle.importKey('jwk', privateKeyJwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);

			const ecdsa2 = await EcdsaCipher.create({ keyPair: { publicKey, privateKey } });
			const isValid = await ecdsa2.verify(signature, data);
			expect(isValid).toBe(true);
		});
	});

	describe('key export', () => {
		it('should export public key as JWK', async () => {
			const ecdsa = await Krypton.create('ECDSA');
			const jwk = await ecdsa.exportPublicKey();
			expect(jwk).toHaveProperty('kty', 'EC');
			expect(jwk).toHaveProperty('crv', 'P-256');
		});

		it('should export private key as JWK', async () => {
			const ecdsa = await Krypton.create('ECDSA');
			const jwk = await ecdsa.exportPrivateKey();
			expect(jwk).toHaveProperty('kty', 'EC');
			expect(jwk).toHaveProperty('d'); // private key component
		});

		it('should export public key in SPKI format', async () => {
			const ecdsa = await Krypton.create('ECDSA');
			const spki = await ecdsa.exportPublicKey('spki');
			expect(spki).toBeInstanceOf(ArrayBuffer);
		});

		it('should export private key in PKCS8 format', async () => {
			const ecdsa = await Krypton.create('ECDSA');
			const pkcs8 = await ecdsa.exportPrivateKey('pkcs8');
			expect(pkcs8).toBeInstanceOf(ArrayBuffer);
		});
	});
});
