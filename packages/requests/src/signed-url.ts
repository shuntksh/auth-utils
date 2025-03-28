import { constantTimeEqual } from "./deps";

/**
 * Generates an HMAC-SHA-256 digest using WebCrypto API
 * @param options - Options object containing:
 *   - key: The key as an ArrayBuffer
 *   - message: The message as an ArrayBuffer
 * @returns Promise resolving to the HMAC digest
 */
const sha256 = async (options: {
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
 * Parameters required for signed URL authentication.
 * Used to pass authentication data via URL parameters.
 */
export type SignedUrlParams = {
	"X-Key": string; // The access key used to sign the URL
	"X-Expires": string; // The expiration time of the URL
	"X-Signature"?: string; // The signature of the URL
	"X-Hostname"?: string; // The hostname of the URL
	"X-Path"?: string; // The path of the URL
	"X-Nonce"?: string; // The nonce of the URL
	[key: string]: string | undefined;
};

/**
 * Error thrown when there are issues with signed URL parameters.
 * Used to provide specific error messages for parameter validation failures.
 */
export class SignedUrlParamError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "SignedUrlParamError";
	}
}

/**
 * Configuration options for creating and verifying signed URLs.
 */
export type SignedUrlOptions = {
	expiresIn?: number;
	maxExpiresIn?: number;
	queryParams?: Record<string, string>;
	nonce?: string;
	logger?: (info: {
		valid: boolean;
		reason?: string;
		context: Record<string, unknown>;
	}) => void;
};

/**
 * Manages URL search parameters for signed URLs.
 * Provides methods to manipulate, validate, and prepare parameters for signing.
 */
export class SignedSearchParams {
	private params: URLSearchParams;
	private readonly reservedParams = [
		"X-Key",
		"X-Expires",
		"X-Signature",
		"X-Hostname",
		"X-Path",
		"X-Nonce",
	];

	constructor(input?: URLSearchParams | string) {
		this.params = new URLSearchParams(input);
	}

	/**
	 * Creates a new URLSearchParams instance from the current parameters.
	 */
	public toURLSearchParams(): URLSearchParams {
		return new URLSearchParams(this.params.toString());
	}

	/**
	 * Gets the value of a parameter.
	 */
	public get(key: string): string | null {
		return this.params.get(key);
	}

	/**
	 * Sets a parameter value.
	 */
	public set(key: string, value: string): this {
		this.params.set(key, value);
		return this;
	}

	/**
	 * Checks if a parameter exists.
	 */
	public has(key: string): boolean {
		return this.params.has(key);
	}

	/**
	 * Removes a parameter.
	 */
	public delete(key: string): this {
		this.params.delete(key);
		return this;
	}

	/**
	 * Returns an iterator of all parameter entries.
	 */
	public entries(): IterableIterator<[string, string]> {
		return this.params.entries();
	}

	/**
	 * Converts parameters to a string.
	 */
	public toString(): string {
		return this.params.toString();
	}

	/**
	 * Sets the required parameters for a signed URL.
	 */
	public setSignedUrlParams(
		key: string,
		expiresAt: number,
		url?: URL,
		nonce?: string,
	): this {
		this.set("X-Key", key);
		this.set("X-Expires", expiresAt.toString());
		if (url) {
			this.set("X-Hostname", url.hostname);
			this.set("X-Path", url.pathname);
		}
		if (nonce) {
			this.set("X-Nonce", nonce);
		}
		return this;
	}

	/**
	 * Adds custom query parameters, ensuring they don't override reserved parameters.
	 */
	public addQueryParams(queryParams: Record<string, string>): this {
		for (const [key, value] of Object.entries(queryParams)) {
			if (key.startsWith("X-") && this.reservedParams.includes(key)) {
				throw new SignedUrlParamError(
					`Cannot override reserved parameter: ${key}`,
				);
			}
			this.set(key, value);
		}
		return this;
	}

	/**
	 * Sets the signature parameter.
	 */
	public setSignature(signature: string): this {
		this.set("X-Signature", signature);
		return this;
	}

	/**
	 * Parses and validates the parameters, returning them as a SignedUrlParams object.
	 */
	public parse(): SignedUrlParams {
		const result: Partial<SignedUrlParams> = {};
		for (const [key, value] of this.entries()) {
			result[key] = value;
		}
		if (!result["X-Key"])
			throw new SignedUrlParamError("Missing required parameter: X-Key");
		if (!result["X-Expires"])
			throw new SignedUrlParamError("Missing required parameter: X-Expires");
		if (result["X-Expires"] && !/^\d+$/.test(result["X-Expires"])) {
			throw new SignedUrlParamError("X-Expires must be a numeric timestamp");
		}
		return result as SignedUrlParams;
	}

	/**
	 * Creates a string to be signed, combining hostname, pathname, and parameters.
	 */
	public createStringToSign(hostname: string, pathname: string): string {
		const paramsForSigning = new SignedSearchParams(this.params);
		paramsForSigning.delete("X-Signature");
		const pathWithQuery = `${pathname}?${paramsForSigning.toString()}`;
		return `${hostname}${pathWithQuery}`;
	}
}

/**
 * Handles cryptographic signing operations.
 * Used internally to generate signatures for URLs.
 */
class Signer {
	private secret: string;

	constructor(secret: string) {
		this.secret = secret;
	}

	/**
	 * Signs a string using HMAC-SHA256 and returns the signature as a base64 string.
	 */
	public async sign(stringToSign: string): Promise<string> {
		const encoder = new TextEncoder();
		const messageBuffer = encoder.encode(stringToSign);
		const keyBuffer = encoder.encode(this.secret);
		const signatureBuffer = await sha256({
			key: keyBuffer,
			message: messageBuffer,
		});
		return btoa(String.fromCharCode(...new Uint8Array(signatureBuffer)));
	}
}

/**
 * Builds signed URLs with authentication parameters.
 * Used to create URLs that can be verified later to ensure they haven't been tampered with.
 */
export class SignedUrlBuilder {
	private params: SignedSearchParams;
	private signer: Signer;
	private key: string;
	private expiresAt: number;
	private url: URL;
	private options: SignedUrlOptions;

	constructor(
		url: string,
		key: string,
		secret: string,
		options?: SignedUrlOptions,
	) {
		this.url = new URL(url);
		this.params = new SignedSearchParams(this.url.search);
		this.key = key;
		this.signer = new Signer(secret);
		this.options = options || {};
		const expiresIn = this.options.expiresIn ?? 15 * 60;
		const maxExpiresIn = this.options.maxExpiresIn ?? 7 * 24 * 60 * 60;
		if (expiresIn <= 0 || expiresIn > maxExpiresIn) {
			throw new SignedUrlParamError(
				expiresIn <= 0
					? "Expiration time must be positive"
					: `Expiration time exceeds maximum allowed (${maxExpiresIn} seconds)`,
			);
		}
		this.expiresAt = Math.floor(Date.now() / 1000) + expiresIn;
	}

	/**
	 * Builds a signed URL by adding authentication parameters and signature.
	 */
	public async build(): Promise<URLSearchParams> {
		this.params.setSignedUrlParams(
			this.key,
			this.expiresAt,
			this.url,
			this.options.nonce,
		);
		if (this.options.queryParams) {
			this.params.addQueryParams(this.options.queryParams);
		}
		const stringToSign = this.params.createStringToSign(
			this.url.hostname,
			this.url.pathname,
		);
		const signature = await this.signer.sign(stringToSign);
		this.params.setSignature(signature);
		return this.params.toURLSearchParams();
	}
}

/**
 * Verifies the authenticity and validity of signed URLs.
 * Used to ensure URLs haven't been tampered with and haven't expired.
 */
class SignedUrlVerifier {
	private params: SignedSearchParams;
	private key: string;
	private signer: Signer;
	private hostname: string;
	private pathname: string;
	private options: Pick<SignedUrlOptions, "logger" | "nonce">;
	private urlType: string;

	constructor(
		url: URL | string | URLSearchParams,
		key: string,
		secret: string,
		options?: Pick<SignedUrlOptions, "logger" | "nonce">,
	) {
		this.key = key;
		this.signer = new Signer(secret);
		this.options = options || {};

		if (url instanceof URL) {
			this.params = new SignedSearchParams(url.search);
			this.hostname = url.hostname;
			this.pathname = url.pathname;
			this.urlType = "URL";
		} else if (typeof url === "string") {
			const urlObj = new URL(url);
			this.params = new SignedSearchParams(urlObj.search);
			this.hostname = urlObj.hostname;
			this.pathname = urlObj.pathname;
			this.urlType = "string";
		} else {
			this.params = new SignedSearchParams(url);
			this.hostname = this.params.get("X-Hostname") || "";
			this.pathname = this.params.get("X-Path") || "";
			this.urlType = "URLSearchParams";
		}
	}

	/**
	 * Verifies the signature, expiration, and other parameters of a signed URL.
	 */
	public async verify(): Promise<{ valid: boolean; reason?: string }> {
		const context: Record<string, unknown> = {
			urlType: this.urlType,
		};

		try {
			const parsedParams = this.params.parse();
			context.parsedParams = { ...parsedParams, "X-Signature": "[REDACTED]" };

			const urlKey = parsedParams["X-Key"];
			const expires = parsedParams["X-Expires"];
			const signature = parsedParams["X-Signature"];
			const urlNonce = parsedParams["X-Nonce"];

			if (!signature)
				return this.logAndReturn(
					{ valid: false, reason: "Missing required parameter: X-Signature" },
					context,
				);
			if (urlKey !== this.key)
				return this.logAndReturn(
					{ valid: false, reason: "Invalid key" },
					context,
				);

			// Check for missing hostname or path when using URLSearchParams
			if (
				this.urlType === "URLSearchParams" &&
				(!this.hostname || !this.pathname)
			) {
				return this.logAndReturn(
					{
						valid: false,
						reason: "Missing hostname or path information in URLSearchParams",
					},
					context,
				);
			}

			const expiresAt = Number.parseInt(expires, 10);
			const currentTime = Math.floor(Date.now() / 1000);
			if (currentTime > expiresAt)
				return this.logAndReturn(
					{ valid: false, reason: "URL has expired" },
					context,
				);

			if (this.options.nonce && urlNonce !== this.options.nonce) {
				return this.logAndReturn(
					{ valid: false, reason: "Invalid nonce" },
					context,
				);
			}

			const stringToVerify = this.params.createStringToSign(
				this.hostname,
				this.pathname,
			);
			const calculatedSignature = await this.signer.sign(stringToVerify);
			const isSignatureValid = constantTimeEqual(
				calculatedSignature,
				signature,
			);

			const result = {
				valid: isSignatureValid,
				reason: isSignatureValid ? undefined : "Invalid signature",
			};
			if (this.options.logger) {
				this.options.logger({
					...result,
					context: { ...context, signatureValid: isSignatureValid },
				});
			}
			return result;
		} catch (error: unknown) {
			const result = {
				valid: false,
				reason: error instanceof Error ? error.message : "Invalid parameters",
			};
			if (this.options.logger) {
				this.options.logger({
					...result,
					context: {
						...context,
						error: error instanceof Error ? error.message : "Unknown error",
					},
				});
			}
			return result;
		}
	}

	/**
	 * Logs verification results if a logger is provided and returns the result.
	 */
	private logAndReturn(
		result: { valid: boolean; reason?: string },
		context: Record<string, unknown>,
	): { valid: boolean; reason?: string } {
		if (this.options.logger) this.options.logger({ ...result, context });
		return result;
	}
}

/**
 * Parses URL search parameters into a SignedUrlParams object.
 * Useful for extracting and validating signed URL parameters from a URLSearchParams object.
 */
export const parseSignedUrlParams = (
	params: URLSearchParams,
): SignedUrlParams => {
	return new SignedSearchParams(params).parse();
};

/**
 * Creates a signed URL with authentication parameters.
 * Used to generate URLs that can be shared and later verified for authenticity.
 */
const createSignedUrl = async (
	url: string,
	key: string,
	secret: string,
	options?: SignedUrlOptions,
): Promise<URLSearchParams> => {
	const builder = new SignedUrlBuilder(url, key, secret, options);
	return builder.build();
};

/**
 * Verifies the authenticity and validity of a signed URL.
 * Used to ensure URLs haven't been tampered with and haven't expired.
 */
const verifySignedUrl = async (
	url: URL | string | URLSearchParams,
	key: string,
	secret: string,
	options?: Pick<SignedUrlOptions, "logger" | "nonce">,
): Promise<{ valid: boolean; reason?: string }> => {
	const verifier = new SignedUrlVerifier(url, key, secret, options);
	return verifier.verify();
};

export { createSignedUrl, verifySignedUrl };
