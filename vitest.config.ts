import { defineConfig } from 'vitest/config';

export default defineConfig({
	resolve: {
    alias: { 'src': new URL('./src', import.meta.url).pathname }
  },
	test: {
		environment: 'node',
		typecheck: { enabled: false },
		coverage: {
			reportsDirectory: './tests/coverage',
			include: ['src/**/*.ts'],
			exclude: [ 'src/types.ts', 'src/index.ts', 'src/ciphers/index.ts' ]
		}
	}
});