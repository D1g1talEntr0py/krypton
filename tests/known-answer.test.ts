import { describe, expect, it } from 'vitest';
import { Krypton } from '../src/krypton.js';

function fromHex(hex: string): Uint8Array<ArrayBuffer> {
	const bytes = new Uint8Array(hex.length / 2);

	for (let i = 0; i < hex.length; i += 2) {
		bytes[i / 2] = Number.parseInt(hex.slice(i, i + 2), 16);
	}

	return bytes;
}

describe('independent known-answer vectors', () => {
	it('matches the NIST AES-128-GCM known-answer vector', async () => {
		// NIST SP 800-38D, GCM test case 2: empty AAD and a 96-bit IV.
		const key = await Krypton.importKey(
			fromHex('00000000000000000000000000000000'),
			Krypton.Algorithm.AES_GCM,
			Krypton.KeyFormat.RAW
		);
		const parameters: AesGcmParams = {
			name: Krypton.Algorithm.AES_GCM,
			iv: fromHex('000000000000000000000000'),
			tagLength: 128
		};
		const plaintext = fromHex('00000000000000000000000000000000');
		const expectedCiphertextAndTag = fromHex(
			'0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf'
		);

		const encrypted = await Krypton.encrypt(parameters, key, plaintext);
		expect(new Uint8Array(encrypted)).toEqual(expectedCiphertextAndTag);
		expect(new Uint8Array(await Krypton.decryptBytes(parameters, key, expectedCiphertextAndTag))).toEqual(plaintext);
	});

	it('matches RFC 4231 HMAC-SHA-256 test case 1', async () => {
		const key = await Krypton.importKey(
			fromHex('0b'.repeat(20)),
			Krypton.Algorithm.HMAC,
			Krypton.KeyFormat.RAW,
			{ hash: Krypton.Hash.SHA_256, usages: ['sign', 'verify'] }
		);
		const expectedSignature = fromHex(
			'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'
		);

		const signature = await Krypton.sign(Krypton.Algorithm.HMAC, key, 'Hi There');
		expect(new Uint8Array(signature)).toEqual(expectedSignature);
		expect(await Krypton.verify(Krypton.Algorithm.HMAC, key, expectedSignature, 'Hi There')).toBe(true);
	});

	it('matches the FIPS 180-4 SHA-256 example for "abc"', async () => {
		const digest = await Krypton.digest(Krypton.Hash.SHA_256, 'abc');

		expect(new Uint8Array(digest)).toEqual(fromHex(
			'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
		));
	});
});
