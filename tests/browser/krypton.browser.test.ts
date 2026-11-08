import { describe, expect, it } from 'vitest';
import { Krypton } from '../../src/krypton.js';

describe('Krypton browser integration (Chromium Web Crypto)', () => {
	it('encrypts and decrypts AES-GCM using the browser crypto implementation and documented wire format', async () => {
		const aes = await Krypton.create(Krypton.Algorithm.AES_GCM);
		const plaintext = 'Krypton browser integration: AES-GCM ✓';
		const encrypted = new Uint8Array(await aes.encrypt(plaintext));
		const rawKey = await aes.exportKey(Krypton.KeyFormat.RAW);
		const key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt']);
		const iv = encrypted.subarray(0, 12);
		const ciphertextAndTag = encrypted.subarray(12);

		expect(iv).toHaveLength(12);
		expect(ciphertextAndTag).toHaveLength(new TextEncoder().encode(plaintext).byteLength + 16);
		expect(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, ciphertextAndTag))
			.toEqual(Krypton.encode(plaintext).buffer);
		expect(await aes.decrypt(encrypted)).toBe(plaintext);

		const tampered = encrypted.slice();
		const lastByteIndex = tampered.length - 1;
		tampered[lastByteIndex] = tampered[lastByteIndex]! ^ 1;
		await expect(aes.decrypt(tampered)).rejects.toThrow();
	});

	it('signs and verifies HMAC-SHA-256 with the browser crypto implementation', async () => {
		const hmac = await Krypton.create(Krypton.Algorithm.HMAC);
		const message = 'Krypton browser integration: HMAC-SHA-256';
		const signature = await hmac.sign(message);
		const rawKey = await hmac.exportKey(Krypton.KeyFormat.RAW);
		const key = await crypto.subtle.importKey(
			'raw',
			rawKey,
			{ name: 'HMAC', hash: 'SHA-256' },
			false,
			['sign', 'verify']
		);
		const nativeSignature = await crypto.subtle.sign('HMAC', key, Krypton.encode(message));

		expect(signature.byteLength).toBe(32);
		expect(new Uint8Array(signature)).toEqual(new Uint8Array(nativeSignature));
		expect(await hmac.verify(signature, message)).toBe(true);
		expect(await crypto.subtle.verify('HMAC', key, signature, Krypton.encode(message))).toBe(true);
		expect(await hmac.verify(signature, `${message}!`)).toBe(false);
	});
});
