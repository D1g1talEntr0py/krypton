import eslint from '@eslint/js';
import { defineConfig } from 'eslint/config';
import jsdoc from 'eslint-plugin-jsdoc';
import tsEslint from 'typescript-eslint';
import tsParser from '@typescript-eslint/parser';
import typeScriptEslint from '@typescript-eslint/eslint-plugin';

export default defineConfig({ ignores: [ 'node_modules/**', 'tests/**', 'dist/**', '*.config.[tj]s' ] }, {
	extends: [
		eslint.configs.recommended,
		jsdoc.configs['flat/recommended-typescript'],
		...tsEslint.configs.recommended,
		...tsEslint.configs.recommendedTypeChecked
	],
	// @ts-expect-error - plugin needs update...
	plugins: { typeScriptEslint, jsdoc },
	languageOptions: {
		parserOptions: {
			project: true,
			parser: tsParser,
			parserOptions: {
				ecmaFeatures: {	impliedStrict: true	}
			},
			tsconfigRootDir: import.meta.dirname,
			allowAutomaticSingleRunInference: true,
			warnOnUnsupportedTypeScriptVersion: false
		}
	},
	settings: {
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
		'jsdoc/require-jsdoc': [ 'error',	{
			exemptEmptyConstructors: true,
			require: {
				ClassDeclaration: true,
				FunctionExpression: true,
				MethodDefinition: true
			}
		}
		],
		indent:  ['error', 'tab', { SwitchCase: 1 } ],
		'linebreak-style': ['error', 'unix'],
		quotes: ['error', 'single'],
		semi: ['error', 'always', {
			omitLastInOneLineBlock: true,
			omitLastInOneLineClassBody: true
		}],
		'@typescript-eslint/unbound-method': 'off',
		'@typescript-eslint/restrict-template-expressions': 'off',
		'@typescript-eslint/no-unsafe-enum-comparison': 'off',
		'@typescript-eslint/method-signature-style': ['error', 'property'],
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