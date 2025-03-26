/**
 * SHA-256 utilities
 */
export const sha256 = async (options: {
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
};

/**
 * AES-CBC-128 utilities (symmetric encryption)
 */
export const AES_CBC_128 = {
	/**
	 * Encrypts a message using AES-CBC-128
	 * @param options - Options object containing:
	 *   - key: The key as BufferSource
	 *   - iv: The initialization vector as BufferSource
	 *   - message: The message as BufferSource
	 * @returns Promise resolving to the encrypted message
	 */
	encrypt: async (options: {
		key: BufferSource;
		iv: BufferSource;
		message: BufferSource;
	}): Promise<ArrayBuffer> => {
		const { key, iv, message } = options;
		const encryptionKey = await crypto.subtle.importKey(
			"raw",
			key,
			{ name: "AES-CBC", length: 128 },
			false,
			["encrypt"],
		);
		const encryptedBuffer = await crypto.subtle.encrypt(
			{ name: "AES-CBC", length: 128, iv },
			encryptionKey,
			message,
		);
		return encryptedBuffer;
	},

	/**
	 * Decrypts a message using AES-CBC-128
	 * @param options - Options object containing:
	 *   - key: The key as BufferSource
	 *   - iv: The initialization vector as BufferSource
	 *   - message: The encrypted message as BufferSource
	 * @returns Promise resolving to the decrypted message
	 */
	decrypt: async (options: {
		key: BufferSource;
		iv: BufferSource;
		message: BufferSource;
	}): Promise<ArrayBuffer> => {
		const { key, iv, message } = options;
		// Decrypt the payload
		const decryptionKey = await crypto.subtle.importKey(
			"raw",
			key,
			{ name: "AES-CBC", length: 128 },
			false,
			["decrypt"],
		);
		return crypto.subtle.decrypt(
			{ name: "AES-CBC", length: 128, iv },
			decryptionKey,
			message,
		);
	},
} as const;
