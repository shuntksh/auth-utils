import { defineConfig } from "tsup";

export default defineConfig({
	entry: [
		"./src/mod.ts",
		"./src/jwt/mod.ts",
		"./src/otp/mod.ts",
		"./src/cbor/mod.ts",
	],
	format: ["esm", "cjs"],
	dts: true,
	clean: true,
	outDir: "dist",
	noExternal: [],
});
