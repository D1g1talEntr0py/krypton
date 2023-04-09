import Krypton from '../src/krypton.js';
import { describe, it, expect } from '@jest/globals';

describe('Krypton AES_CBC', () => {
	it('should encode and decode a string', async () => {
		const data = 'Hello, World!';
		const krypton = new Krypton(Krypton.Algorithm.AES_CBC);
		const encrypted = await krypton.encrypt(data);
		const decrypted = await krypton.decrypt(encrypted);
		expect(decrypted).toEqual(data);
	});
});

describe('Krypton AES_CTR', () => {
	it('should encode and decode a string', async () => {
		const data = 'Hello, World!';
		const krypton = new Krypton(Krypton.Algorithm.AES_CTR);
		const encrypted = await krypton.encrypt(data);
		const decrypted = await krypton.decrypt(encrypted);
		expect(decrypted).toEqual(data);
	});
});

describe('Krypton AES_GCM', () => {
	it('should encode and decode a string', async () => {
		const data = 'Hello, World!';
		const krypton = new Krypton(Krypton.Algorithm.AES_GCM);
		const encrypted = await krypton.encrypt(data);
		const decrypted = await krypton.decrypt(encrypted);
		expect(decrypted).toEqual(data);
	});
});

describe('Krypton RSA_OAEP', () => {
	it('should encode and decode a string', async () => {
		const data = 'Hello, World!';
		const krypton = new Krypton(Krypton.Algorithm.RSA_OAEP);
		const encrypted = await krypton.encrypt(data);
		const decrypted = await krypton.decrypt(encrypted);
		expect(decrypted).toEqual(data);
	});

	it('should encode and decode a string with a key pair', async () => {
		const data = 'Hello, World!';
		const krypton = new Krypton(Krypton.Algorithm.RSA_OAEP);
		const keyPair = await Krypton.generateKey(Krypton.Algorithm.RSA_OAEP);
		const encrypted = await krypton.encrypt(data, keyPair);
		const decrypted = await krypton.decrypt(encrypted, keyPair);
		expect(decrypted).toEqual(data);
	});

	it('should encode and decode a string with a key pair passed to the constructor', async () => {
		const data = 'Hello, World!';
		const keyPair = await Krypton.generateKey(Krypton.Algorithm.RSA_OAEP);
		const krypton = new Krypton(Krypton.Algorithm.RSA_OAEP, keyPair);
		const encrypted = await krypton.encrypt(data);
		const decrypted = await krypton.decrypt(encrypted);
		expect(decrypted).toEqual(data);
	});
});
