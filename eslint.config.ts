import eslint from '@eslint/js';
import tslint from 'typescript-eslint';
import eslintPluginCompat from 'eslint-plugin-compat';
import jsdoc from 'eslint-plugin-jsdoc';
import { defineConfig } from 'eslint/config';

export default defineConfig({
	extends: [
		eslint.configs.recommended,
		...tslint.configs.recommended,
		...tslint.configs.recommendedTypeChecked,
		jsdoc.configs['flat/recommended-typescript'],
		eslintPluginCompat.configs['flat/recommended']
	],
	ignores: ['node_modules/**', 'dist/**', 'tests/**', '*.config.ts'],
	plugins: { '@typescript-eslint': tslint.plugin, eslintPluginCompat, jsdoc },
	languageOptions: {
		parser: tslint.parser,
		parserOptions: {
			project: true,
			ecmaFeatures: { impliedStrict: true },
			tsconfigRootDir: import.meta.dirname,
			allowAutomaticSingleRunInference: true,
			warnOnUnsupportedTypeScriptVersion: false
		}
	},
	settings: {
		lintAllEsApis: true,
		jsdoc: {
			mode: 'typescript',
			structuredTags: {
				template: { name: 'namepath-defining', type: true }
			}
		}
	},
	rules: {
		'jsdoc/check-param-names': [ 'error', { checkDestructured: false	}	],
		'jsdoc/require-param': [ 'error',	{ checkDestructured: false } ],
		'jsdoc/tag-lines': 0,
		'jsdoc/no-defaults': 0,
		indent: [ 'error', 'tab', { SwitchCase: 1 } ],
		'linebreak-style': [ 'error', 'unix' ],
		quotes: [ 'error', 'single' ],
		semi: [ 'error', 'always', { omitLastInOneLineBlock: true, omitLastInOneLineClassBody: true } ],
		'@typescript-eslint/unbound-method': 'off',
		'@typescript-eslint/restrict-template-expressions': 'off',
		'@typescript-eslint/no-unsafe-enum-comparison': 'off',
		'@typescript-eslint/no-unused-vars': ['error', {
			args: 'all',
			argsIgnorePattern: '^_',
			caughtErrors: 'all',
			caughtErrorsIgnorePattern: '^_',
			destructuredArrayIgnorePattern: '^_',
			varsIgnorePattern: '^_',
			ignoreRestSiblings: true
		}]
	}
});