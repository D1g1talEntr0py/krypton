import { defineConfig } from 'vitest/config';

export default defineConfig({
	test: {
		environment: 'node',
		coverage: {
			reportsDirectory: './tests/coverage',
			include: ['src/**/*.ts'],
			exclude: [ 'src/types.ts', 'src/index.ts', 'src/ciphers/index.ts' ]
		}
	}
});