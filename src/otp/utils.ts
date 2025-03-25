/**
 * Constant-time comparison of two Uint8Arrays or strings
 */
export function constantTimeEqual(a: string, b: string): boolean {
	if (typeof a === "string" && typeof b === "string") {
		if (a.length !== b.length) return false;
		let result = 0;
		for (let i = 0; i < a.length; i++) {
			result |= a.charCodeAt(i) ^ b.charCodeAt(i);
		}
		return result === 0;
	}
	throw new Error("Invalid input");
}

/**
 * HMAC utilities
 */
export const HMAC = {
	/**
	 * Generates an HMAC-SHA-1 digest using WebCrypto API
	 * @param options - Options object containing:
	 *   - key: The key as an ArrayBuffer
	 *   - message: The message as an ArrayBuffer
	 * @returns Promise resolving to the HMAC digest
	 */
	sha1: async (options: {
		key: BufferSource;
		message: BufferSource;
	}): Promise<ArrayBuffer> => {
		const { key, message } = options;
		const cryptoKey = await crypto.subtle.importKey(
			"raw",
			key,
			{ name: "HMAC", hash: { name: "SHA-1" } },
			false,
			["sign"],
		);

		return crypto.subtle.sign("HMAC", cryptoKey, message);
	},

	/**
	 * Generates an HMAC-SHA-256 digest using WebCrypto API
	 * @param options - Options object containing:
	 *   - key: The key as an ArrayBuffer
	 *   - message: The message as an ArrayBuffer
	 * @returns Promise resolving to the HMAC digest
	 */
	sha256: async (options: {
		key: BufferSource;
		message: BufferSource;
	}): Promise<ArrayBuffer> => {
		const { key, message } = options;
		const cryptoKey = await crypto.subtle.importKey(
			"raw",
			key,
			{ name: "HMAC", hash: { name: "SHA-256" } },
			false,
			["sign"],
		);

		return crypto.subtle.sign("HMAC", cryptoKey, message);
	},
} as const;
