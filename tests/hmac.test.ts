import { describe, it, expect } from 'vitest';
import { Krypton } from '../src/krypton.js';
import { HmacCipher } from '../src/ciphers/hmac.js';

describe('HmacCipher', () => {
	describe('create', () => {
		it('should create an HMAC cipher via Krypton.create', async () => {
			const hmac = await Krypton.create('HMAC');
			expect(hmac).toBeInstanceOf(HmacCipher);
		});

		it('should create from an existing CryptoKey', async () => {
			const key = await Krypton.generateKey(Krypton.Algorithm.HMAC, { usages: ['sign', 'verify'] }) as CryptoKey;
			const hmac = await HmacCipher.create({ key });
			expect(hmac).toBeInstanceOf(HmacCipher);
		});

		it('should create from a JsonWebKey', async () => {
			const key = await Krypton.generateKey(Krypton.Algorithm.HMAC, { usages: ['sign', 'verify'] }) as CryptoKey;
			const jwk = await Krypton.exportKey(key);
			const hmac = await HmacCipher.create({ key: jwk });
			expect(hmac).toBeInstanceOf(HmacCipher);
		});
	});

	describe('sign / verify', () => {
		it('should sign and verify a string', async () => {
			const hmac = await Krypton.create('HMAC');
			const data = 'Hello, HMAC!';
			const signature = await hmac.sign(data);
			expect(signature).toBeInstanceOf(ArrayBuffer);
			const isValid = await hmac.verify(signature, data);
			expect(isValid).toBe(true);
		});

		it('should reject tampered data', async () => {
			const hmac = await Krypton.create('HMAC');
			const signature = await hmac.sign('original data');
			const isValid = await hmac.verify(signature, 'tampered data');
			expect(isValid).toBe(false);
		});

		it('should reject a tampered signature', async () => {
			const hmac = await Krypton.create('HMAC');
			const data = 'test data';
			const signature = await hmac.sign(data);
			const tampered = new Uint8Array(signature);
			tampered[0] ^= 0xff;
			const isValid = await hmac.verify(tampered.buffer, data);
			expect(isValid).toBe(false);
		});

		it('should sign and verify BufferSource data', async () => {
			const hmac = await Krypton.create('HMAC');
			const data = Krypton.encode('binary data');
			const signature = await hmac.sign(data);
			const isValid = await hmac.verify(signature, data);
			expect(isValid).toBe(true);
		});

		it('should sign and verify unicode and emoji', async () => {
			const hmac = await Krypton.create('HMAC');
			const data = '🔑 認証 テスト 🔐';
			const signature = await hmac.sign(data);
			const isValid = await hmac.verify(signature, data);
			expect(isValid).toBe(true);
		});

		it('should produce consistent signatures for the same key and data', async () => {
			const hmac = await Krypton.create('HMAC');
			const data = 'consistent';
			const sig1 = await hmac.sign(data);
			const sig2 = await hmac.sign(data);
			const s1 = new Uint8Array(sig1);
			const s2 = new Uint8Array(sig2);
			expect(s1).toEqual(s2);
		});
	});

	describe('key export / import', () => {
		it('should export and reimport a key', async () => {
			const hmac1 = await Krypton.create('HMAC');
			const data = 'Cross-instance signing';
			const signature = await hmac1.sign(data);

			const exportedKey = await hmac1.exportKey();
			const hmac2 = await HmacCipher.create({ key: exportedKey as JsonWebKey });
			const isValid = await hmac2.verify(signature, data);
			expect(isValid).toBe(true);
		});

		it('should export key as raw ArrayBuffer', async () => {
			const hmac = await Krypton.create('HMAC');
			const raw = await hmac.exportKey('raw');
			expect(raw).toBeInstanceOf(ArrayBuffer);
			expect(raw.byteLength).toBeGreaterThan(0);
		});
	});
});
