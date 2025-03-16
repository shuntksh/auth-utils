// @cspell:disable
import { describe, expect } from "bun:test";
import { fc, test } from "fast-check-bun-test";

import { base32 } from "./base32";

describe("Base32", () => {
	test("should correctly encode and decode", () => {
		// Test vectors
		const testCases = [
			{ input: "Hello", expected: "JBSWY3DP" },
			{ input: "Test", expected: "KRSXG5A=" },
			{ input: "12345", expected: "GEZDGNBV" },
			{ input: "", expected: "" },
		];

		for (const { input, expected } of testCases) {
			const encoder = new TextEncoder();
			const buffer = encoder.encode(input);
			const output = base32.fromBuffer(buffer);
			expect(output).toBe(expected);

			const decoded = base32.toBuffer(output);
			const decoder = new TextDecoder();
			const result = decoder.decode(decoded);
			expect(result).toBe(input);
		}
	});

	test("should throw on invalid base32 characters", () => {
		expect(() => base32.toBuffer("INVALID!")).toThrow(
			"Invalid base32 character: !",
		);
	});

	test("property: encode -> decode roundtrip", () => {
		fc.assert(
			fc.property(fc.string(), (str) => {
				const encoder = new TextEncoder();
				const buffer = encoder.encode(str);
				const output = base32.fromBuffer(buffer);
				const decoded = base32.toBuffer(output);
				const decoder = new TextDecoder();
				const result = decoder.decode(decoded);
				return result === str;
			}),
		);
	});
});
