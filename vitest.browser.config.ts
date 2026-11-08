import { playwright } from '@vitest/browser-playwright';
import { defineConfig } from 'vitest/config';

export default defineConfig({
	resolve: {
		alias: { src: new URL('./src', import.meta.url).pathname }
	},
	test: {
		include: ['tests/browser/**/*.test.ts'],
		typecheck: { enabled: false },
		browser: {
			provider: playwright(),
			headless: true,
			instances: [{ browser: 'chromium' }]
		}
	}
});
