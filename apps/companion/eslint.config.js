import js from '@eslint/js'
import tseslint from 'typescript-eslint'
import reactHooks from 'eslint-plugin-react-hooks'

export default tseslint.config(
  { ignores: ['dist', 'src-tauri', 'playwright-report', 'test-results'] },
  js.configs.recommended,
  tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname
      }
    }
  },
  reactHooks.configs['recommended-latest'],
  {
    rules: {
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
    files: ['scripts/**/*.mjs', 'playwright.config.ts', 'vite.config.ts'],
    ...tseslint.configs.disableTypeChecked
  }
)
