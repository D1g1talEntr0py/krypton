import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';

const cipherModules = new Set();

registerHooks({
	load(url, context, nextLoad) {
		if (/\/dist\/ciphers\/[^/]+\.js$/.test(new URL(url).pathname)) {
			cipherModules.add(new URL(url).pathname.split('/').at(-1));
		}

		return nextLoad(url, context);
	}
});

const { Krypton } = await import('@d1g1tal/krypton');
assert.equal(typeof Krypton, 'function', 'the package root should export Krypton');
assert.deepEqual([...cipherModules], [], 'importing the package root should not load cipher modules');

await Krypton.create('AES-GCM');
assert.deepEqual([...cipherModules], ['aes.js'], 'creating an AES cipher should load only the AES module');

const cipherExports = [
	['aes', 'AesCipher'],
	['rsa', 'RsaCipher'],
	['hmac', 'HmacCipher'],
	['ecdsa', 'EcdsaCipher'],
	['ecdh', 'EcdhCipher']
];

for (const [subpath, exportName] of cipherExports) {
	const cipherModule = await import(`@d1g1tal/krypton/ciphers/${subpath}`);
	assert.equal(typeof cipherModule[exportName], 'function', `the ${subpath} subpath should export ${exportName}`);
}

console.log('Package exports and lazy-loading smoke test passed.');
