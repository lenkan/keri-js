import globals from "globals";
import pluginJs from "@eslint/js";
import tseslint from "typescript-eslint";
import prettier from "eslint-config-prettier";

export default tseslint.config(
  { ignores: ["node_modules", "dist"] },
  {
    files: ["**/*.{js,mjs,cjs,ts}"],
    extends: [pluginJs.configs.recommended, tseslint.configs.strict, tseslint.configs.stylistic],
    languageOptions: { globals: globals["shared-node-browser"] },
  },
  { rules: prettier.rules },
  {
    rules: {
      "no-console": "error",
      "@typescript-eslint/consistent-type-imports": ["error", { fixStyle: "inline-type-imports" }],
      "@typescript-eslint/parameter-properties": "error",
    },
  },
  {
    files: ["src/cli/**/*.ts", "scripts/**/*.ts"],
    rules: { "no-console": "off" },
  },
);
