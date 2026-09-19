import js from '@eslint/js'
import tseslint from 'typescript-eslint'
import reactHooks from 'eslint-plugin-react-hooks'

export default tseslint.config(
  {
    ignores: [
      'dist',
      'dist-harness',
      'src-tauri',
      'playwright-report',
      'test-results',
      // The linter's own configuration is not linted.
      'eslint.config.js'
    ]
  },
  js.configs.recommended,
  tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        // Both projects: the application's own files, and the build configuration beside them.
        project: ['./tsconfig.json', './tsconfig.node.json'],
        tsconfigRootDir: import.meta.dirname
      }
    }
  },
  {
    plugins: { 'react-hooks': reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // The WebView is the least trusted surface in the product. A renderer that wrote markup
      // would be the one way a package could put an element on the page, so nothing may.
      'no-restricted-properties': [
        'error',
        {
          object: 'document',
          property: 'write',
          message: 'The interface builds elements; it never writes markup.'
        }
      ],
      'no-restricted-syntax': [
        'error',
        {
          selector: 'JSXAttribute[name.name="dangerouslySetInnerHTML"]',
          message: 'Nothing in this application turns a string into markup.'
        },
        {
          selector: 'MemberExpression[property.name="innerHTML"]',
          message: 'Nothing in this application turns a string into markup.'
        },
        {
          selector: 'MemberExpression[property.name="outerHTML"]',
          message: 'Nothing in this application turns a string into markup.'
        },
        {
          selector: 'NewExpression[callee.name="Function"]',
          message: 'The bundle evaluates no code it was not built with.'
        },
        {
          selector: 'CallExpression[callee.name="eval"]',
          message: 'The bundle evaluates no code it was not built with.'
        }
      ]
    }
  },
  {
    files: ['scripts/**/*.mjs'],
    ...tseslint.configs.disableTypeChecked,
    languageOptions: {
      globals: { process: 'readonly', console: 'readonly' }
    }
  },
  {
    // A test drives the interface the way a person does, including handing it the failure shape a
    // command actually rejects with, which is data rather than an Error.
    files: ['test/**/*.ts', 'test/**/*.tsx'],
    rules: {
      '@typescript-eslint/prefer-promise-reject-errors': 'off',
      '@typescript-eslint/require-await': 'off'
    }
  }
)
