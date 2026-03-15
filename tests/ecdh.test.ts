import { describe, it, expect } from 'vitest';
import { Krypton } from '../src/krypton.js';
import { EcdhCipher } from '../src/ciphers/ecdh.js';

describe('EcdhCipher', () => {
	describe('create', () => {
		it('should create an ECDH cipher via Krypton.create', async () => {
			const ecdh = await Krypton.create('ECDH');
			expect(ecdh).toBeInstanceOf(EcdhCipher);
		});

		it('should create from an existing key pair', async () => {
			const keyPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']) as CryptoKeyPair;
			const ecdh = await EcdhCipher.create({ keyPair });
			expect(ecdh).toBeInstanceOf(EcdhCipher);
		});
	});

	describe('deriveKey', () => {
		it('should derive a shared AES-GCM key between two parties', async () => {
			const alice = await Krypton.create('ECDH');
			const bob = await Krypton.create('ECDH');

			const alicePublicJwk = await alice.exportPublicKey();
			const bobPublicJwk = await bob.exportPublicKey();

			const alicePublicKey = await crypto.subtle.importKey('jwk', alicePublicJwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
			const bobPublicKey = await crypto.subtle.importKey('jwk', bobPublicJwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []);

			const aliceSharedKey = await alice.deriveKey(bobPublicKey);
			const bobSharedKey = await bob.deriveKey(alicePublicKey);

			// Both parties should derive the same key
			const aliceExported = await Krypton.exportKey(aliceSharedKey, 'raw');
			const bobExported = await Krypton.exportKey(bobSharedKey, 'raw');
			expect(new Uint8Array(aliceExported)).toEqual(new Uint8Array(bobExported));
		});

		it('should derive a key usable for encryption', async () => {
			const alice = await Krypton.create('ECDH');
			const bob = await Krypton.create('ECDH');

			const alicePublicJwk = await alice.exportPublicKey();
			const bobPublicJwk = await bob.exportPublicKey();

			const alicePublicKey = await crypto.subtle.importKey('jwk', alicePublicJwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
			const bobPublicKey = await crypto.subtle.importKey('jwk', bobPublicJwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []);

			const aliceSharedKey = await alice.deriveKey(bobPublicKey);
			const bobSharedKey = await bob.deriveKey(alicePublicKey);

			// Alice encrypts, Bob decrypts
			const data = 'Secret message between Alice and Bob';
			const params = Krypton.generateParameters();
			const encrypted = await Krypton.encrypt(params, aliceSharedKey, data);
			const decrypted = await Krypton.decrypt(params, bobSharedKey, encrypted);
			expect(decrypted).toEqual(data);
		});

		it('should derive an HMAC key', async () => {
			const alice = await Krypton.create('ECDH');
			const bob = await Krypton.create('ECDH');

			const bobPublicJwk = await bob.exportPublicKey();
			const bobPublicKey = await crypto.subtle.importKey('jwk', bobPublicJwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []);

			const hmacKey = await alice.deriveKey(bobPublicKey, { name: 'HMAC', hash: 'SHA-256', length: 256 }, { usages: ['sign', 'verify'] });
			expect(hmacKey.algorithm.name).toBe('HMAC');
		});
	});

	describe('deriveBits', () => {
		it('should derive raw bits from the shared secret', async () => {
			const alice = await Krypton.create('ECDH');
			const bob = await Krypton.create('ECDH');

			const alicePublicJwk = await alice.exportPublicKey();
			const bobPublicJwk = await bob.exportPublicKey();

			const alicePublicKey = await crypto.subtle.importKey('jwk', alicePublicJwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
			const bobPublicKey = await crypto.subtle.importKey('jwk', bobPublicJwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []);

			const aliceBits = await alice.deriveBits(bobPublicKey);
			const bobBits = await bob.deriveBits(alicePublicKey);

			expect(aliceBits).toBeInstanceOf(ArrayBuffer);
			expect(aliceBits.byteLength).toBe(32); // 256 bits
			expect(new Uint8Array(aliceBits)).toEqual(new Uint8Array(bobBits));
		});

		it('should derive a custom number of bits', async () => {
			const alice = await Krypton.create('ECDH');
			const bob = await Krypton.create('ECDH');

			const bobPublicJwk = await bob.exportPublicKey();
			const bobPublicKey = await crypto.subtle.importKey('jwk', bobPublicJwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []);

			const bits = await alice.deriveBits(bobPublicKey, 128);
			expect(bits.byteLength).toBe(16); // 128 bits
		});
	});

	describe('key export', () => {
		it('should export public key as JWK', async () => {
			const ecdh = await Krypton.create('ECDH');
			const jwk = await ecdh.exportPublicKey();
			expect(jwk).toHaveProperty('kty', 'EC');
			expect(jwk).toHaveProperty('crv', 'P-256');
		});

		it('should export private key as JWK', async () => {
			const ecdh = await Krypton.create('ECDH');
			const jwk = await ecdh.exportPrivateKey();
			expect(jwk).toHaveProperty('kty', 'EC');
			expect(jwk).toHaveProperty('d'); // private key component
		});

		it('should export public key in SPKI format', async () => {
			const ecdh = await Krypton.create('ECDH');
			const spki = await ecdh.exportPublicKey('spki');
			expect(spki).toBeInstanceOf(ArrayBuffer);
		});

		it('should export private key in PKCS8 format', async () => {
			const ecdh = await Krypton.create('ECDH');
			const pkcs8 = await ecdh.exportPrivateKey('pkcs8');
			expect(pkcs8).toBeInstanceOf(ArrayBuffer);
		});
	});
});
