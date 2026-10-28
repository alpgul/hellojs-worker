import js from '@eslint/js'
import prettier from 'eslint-config-prettier/flat'
import importX from 'eslint-plugin-import-x'
import globals from 'globals'
import tseslint from 'typescript-eslint'
import unicorn from 'eslint-plugin-unicorn'

// Flat ESLint config. JavaScript and TypeScript sources are both ESM.
export default tseslint.config(
	{
		ignores: [
			'node_modules/**',
			'dist/**',
			'coverage/**',
			'test/fixtures/**',
			'chrome-response-*.json',
			'leaf*.pem',
			'leaf*.der',
		],
	},
	js.configs.recommended,
	importX.flatConfigs.recommended,
	{
		files: ['**/*.{js,mjs,cjs,ts,mts,cts}'],
		languageOptions: {
			ecmaVersion: 2024,
			sourceType: 'module',
			globals: {
				...globals.node,
				...globals.nodeBuiltin,
			},
		},
		plugins: { unicorn },
		settings: {
			'import-x/resolver': {
				node: { extensions: ['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.json'] },
			},
		},
		rules: {
			'no-unused-vars': ['warn', { args: 'none', varsIgnorePattern: '^_', caughtErrors: 'none' }],
			'no-empty': ['warn', { allowEmptyCatch: true }],
			'no-cond-assign': ['error', 'except-parens'],
			'no-constant-condition': ['error', { checkLoops: false }],
			'no-prototype-builtins': 'off',
			'no-var': 'error',
			'no-else-return': 'warn',
			'prefer-const': ['warn', { destructuring: 'all' }],
			'prefer-object-spread': 'warn',
			'object-shorthand': ['warn', 'properties'],
			eqeqeq: ['warn', 'smart'],

			// TypeScript already validates module resolution during the migration.
			'import-x/no-unresolved': 'off',
			'import-x/no-named-as-default': 'off',
			'import-x/no-named-as-default-member': 'off',
			'import-x/default': 'off',
			'import-x/namespace': 'off',
			'import-x/named': 'off',
			'import-x/order': [
				'warn',
				{
					groups: ['builtin', 'external', 'internal', 'parent', 'sibling', 'index', 'object', 'type'],
					'newlines-between': 'always',
					alphabetize: { order: 'asc', caseInsensitive: true },
				},
			],
			'import-x/newline-after-import': 'warn',
			'import-x/no-duplicates': 'warn',
			'import-x/no-useless-path-segments': 'warn',

			// Curated unicorn subset: correctness and low-noise readability rules.
			// The full recommended preset is too opinionated for a protocol codebase.
			'unicorn/error-message': 'error',
			'unicorn/escape-case': 'warn',
			'unicorn/new-for-builtins': 'error',
			'unicorn/no-instanceof-builtins': 'warn',
			'unicorn/no-invalid-remove-event-listener': 'error',
			'unicorn/no-lonely-if': 'warn',
			'unicorn/no-new-buffer': 'error',
			'unicorn/no-thenable': 'error',
			'unicorn/no-useless-fallback-in-spread': 'warn',
			'unicorn/no-useless-spread': 'warn',
			'unicorn/prefer-array-find': 'warn',
			'unicorn/prefer-array-flat-map': 'warn',
			'unicorn/prefer-array-some': 'warn',
			'unicorn/prefer-at': 'warn',
			'unicorn/prefer-includes': 'warn',
			'unicorn/prefer-logical-operator-over-ternary': 'warn',
			'unicorn/prefer-negative-index': 'warn',
			'unicorn/prefer-node-protocol': 'warn',
			'unicorn/prefer-number-properties': 'warn',
			'unicorn/prefer-object-from-entries': 'warn',
			'unicorn/prefer-optional-catch-binding': 'warn',
			'unicorn/prefer-set-has': 'warn',
			'unicorn/prefer-string-replace-all': 'warn',
			'unicorn/require-array-sort-compare': 'warn',
			'unicorn/switch-case-braces': 'warn',
			'unicorn/throw-new-error': 'error',
		},
	},
	{
		files: ['**/*.ts'],
		extends: [...tseslint.configs.recommended, importX.flatConfigs.typescript],
		rules: {
			'no-undef': 'off',
			'no-unused-vars': 'off',
			'@typescript-eslint/no-unused-vars': [
				'warn',
				{ args: 'none', varsIgnorePattern: '^_', caughtErrors: 'none' },
			],
			'@typescript-eslint/consistent-type-imports': 'warn',
			'@typescript-eslint/no-explicit-any': 'warn',
		},
	},
	prettier,
)
