// ESLint flat config for the FeatherReader OAuth sidecar (TypeScript/Node ESM).
//
//   npm run lint        # report
//   npm run lint:fix    # autofix
//
// Runs in CI (see .github/workflows/ci.yml, job `sidecar`). Uses the
// typescript-eslint *recommended* (non-type-checked) preset — fast, no
// tsconfig-project resolution needed, and it already flags the mistakes that
// matter here. `eslint-config-prettier` is applied LAST so ESLint never fights
// Prettier over formatting (Prettier owns whitespace; ESLint owns correctness).
import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import prettier from 'eslint-config-prettier';

export default tseslint.config(
  {
    // Build output + deps are never linted.
    ignores: ['dist/', 'dist-test/', 'node_modules/'],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['**/*.ts'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
    },
    rules: {
      // A confidential-client sidecar should not leak to stdout/stderr casually;
      // the two deliberate boot-time warnings in config.ts carry explicit
      // `eslint-disable-next-line no-console` directives (which this rule makes
      // meaningful — keeping the source's intent and the lint honest).
      'no-console': 'error',
      // Unused vars are an error, but allow the conventional `_`-prefix escape
      // hatch for deliberately-ignored args/caught errors.
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
        },
      ],
    },
  },
  // Must be last: turns off every stylistic rule that would conflict with
  // Prettier.
  prettier,
);
