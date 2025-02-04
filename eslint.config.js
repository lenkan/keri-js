import globals from "globals";
import pluginJs from "@eslint/js";
import tseslint from "typescript-eslint";
import prettier from "eslint-config-prettier";

export default tseslint.config(
  { ignores: ["node_modules", "dist", "packages/*/dist", "packages/*/node_modules", ".venv", ".keri", ".pack"] },
  {
    files: ["**/*.{js,mjs,cjs,ts}"],
    extends: [pluginJs.configs.recommended, tseslint.configs.strict, tseslint.configs.stylistic],
    languageOptions: { globals: globals["shared-node-browser"] },
  },
  { rules: prettier.rules },
  {
    rules: {
      // Rules for --experimental-strip-types to work
      "@typescript-eslint/consistent-type-imports": "error",
      "@typescript-eslint/parameter-properties": "error",
    },
  },
);
