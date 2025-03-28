/**
 * RFC 6749: OAuth 2.0 Authorization Framework
 *
 * This module provides functionality for OAuth 2.0 authorization flows:
 * - Authorization Code Grant (with PKCE)
 * - Client Credentials Grant
 * - Refresh Token Grant
 *
 * Core protocol implementation based on RFC 6749, with provider-specific
 * configurations moved to the providers.ts module.
 */

import { base64Url, OIDCError } from "./deps";
import { PKCE, type PKCEParams } from "./pkce";

/**
 * OAuth 2.0 Grant Types
 */
export const GrantTypes = {
	AUTHORIZATION_CODE: "authorization_code",
	CLIENT_CREDENTIALS: "client_credentials",
	REFRESH_TOKEN: "refresh_token",
} as const;

export type GrantType = (typeof GrantTypes)[keyof typeof GrantTypes];

/**
 * OAuth 2.0 Response Types
 */
export const ResponseTypes = {
	CODE: "code",
	TOKEN: "token",
} as const;

export type ResponseType = (typeof ResponseTypes)[keyof typeof ResponseTypes];

/**
 * OAuth 2.0 Provider Configuration
 */
export interface OAuth2ProviderConfig {
	provider: string;
	authorizationEndpoint: string;
	tokenEndpoint: string;
	revocationEndpoint?: string;
	clientId: string;
	clientSecret?: string | (() => string | Promise<string>);
	redirectUri: string;
	defaultScopes?: string[];
	additionalAuthParams?: Record<string, string>;
	additionalTokenParams?: Record<string, string>;
	usePKCE?: boolean;
	allowedRedirectUris?: string[];
}

/**
 * OAuth 2.0 Token Response
 */
export interface OAuth2TokenResponse {
	access_token: string;
	token_type: string;
	expires_in?: number;
	refresh_token?: string;
	scope?: string;
	id_token?: string;
	[key: string]: unknown;
}

/**
 * OAuth 2.0 Error Response
 */
export interface OAuth2ErrorResponse {
	error: string;
	error_description?: string;
	error_uri?: string;
}

/**
 * OAuth 2.0 Authorization Request Options
 */
export interface AuthorizationRequestOptions {
	config: OAuth2ProviderConfig;
	responseType?: ResponseType;
	scopes?: string[];
	state?: string;
	pkce?: PKCEParams;
	additionalParams?: Record<string, string>;
}

/**
 * OAuth 2.0 Token Request Options
 */
export interface TokenRequestOptions {
	config: OAuth2ProviderConfig;
	grantType: GrantType;
	code?: string;
	refreshToken?: string;
	codeVerifier?: string;
	additionalParams?: Record<string, string>;
}

/**
 * OAuth 2.0 Token Revocation Options
 */
export interface TokenRevocationOptions {
	config: OAuth2ProviderConfig;
	token: string;
	tokenTypeHint?: "access_token" | "refresh_token";
}

/**
 * Validation utility functions
 */

/**
 * Validation utility functions
 */
const _validate = {
	validateConfig(config: OAuth2ProviderConfig) {
		if (!config.clientId) throw new OIDCError("clientId is required");
		if (!config.redirectUri.match(/^https:\/\//)) {
			throw new OIDCError("redirectUri must use HTTPS");
		}
		if (!config.authorizationEndpoint.match(/^https:\/\//)) {
			throw new OIDCError("authorizationEndpoint must use HTTPS");
		}
		if (!config.tokenEndpoint.match(/^https:\/\//)) {
			throw new OIDCError("tokenEndpoint must use HTTPS");
		}
	},

	validateRedirectUri(config: OAuth2ProviderConfig, redirectUri: string) {
		if (
			config.allowedRedirectUris &&
			!config.allowedRedirectUris.includes(redirectUri)
		) {
			throw new OIDCError("Invalid redirect_uri: not in allowed list");
		}
	},
};

/**
 * OAuth 2.0 Client
 */
export const OAuth2 = {
	createAuthorizationUrl,
	exchangeCodeForTokens,
	refreshAccessToken,
	revokeToken,
	getClientCredentialsToken,
	generatePKCE: PKCE.generate,
} as const;

function createAuthorizationUrl(options: AuthorizationRequestOptions): string {
	const {
		config,
		responseType = ResponseTypes.CODE,
		scopes,
		state,
		pkce,
		additionalParams,
	} = options;

	_validate.validateConfig(config);
	_validate.validateRedirectUri(config, config.redirectUri);

	const url = new URL(config.authorizationEndpoint);

	url.searchParams.append("client_id", config.clientId);
	url.searchParams.append("redirect_uri", config.redirectUri);
	url.searchParams.append("response_type", responseType);

	const scopeList = scopes || config.defaultScopes || [];
	if (scopeList.length > 0) {
		url.searchParams.append("scope", scopeList.join(" "));
	}

	if (state) {
		url.searchParams.append("state", state);
	}

	if (config.usePKCE && pkce) {
		url.searchParams.append("code_challenge", pkce.codeChallenge);
		url.searchParams.append("code_challenge_method", pkce.codeChallengeMethod);
	}

	if (config.additionalAuthParams) {
		for (const [key, value] of Object.entries(config.additionalAuthParams)) {
			url.searchParams.append(key, value);
		}
	}

	if (additionalParams) {
		for (const [key, value] of Object.entries(additionalParams)) {
			url.searchParams.append(key, value);
		}
	}

	return url.toString();
}

async function exchangeCodeForTokens(
	options: TokenRequestOptions,
): Promise<OAuth2TokenResponse> {
	const { config, code, codeVerifier, additionalParams } = options;

	_validate.validateConfig(config);
	_validate.validateRedirectUri(config, config.redirectUri);

	if (!code) {
		throw new OIDCError("Authorization code is required");
	}

	const params = new URLSearchParams();
	params.append("grant_type", GrantTypes.AUTHORIZATION_CODE);
	params.append("code", code);
	params.append("redirect_uri", config.redirectUri);
	params.append("client_id", config.clientId);

	if (config.clientSecret) {
		const secret =
			typeof config.clientSecret === "function"
				? await config.clientSecret()
				: config.clientSecret;
		params.append("client_secret", secret);
	}

	if (config.usePKCE && codeVerifier) {
		params.append("code_verifier", codeVerifier);
	}

	if (config.additionalTokenParams) {
		for (const [key, value] of Object.entries(config.additionalTokenParams)) {
			params.append(key, value);
		}
	}

	if (additionalParams) {
		for (const [key, value] of Object.entries(additionalParams)) {
			params.append(key, value);
		}
	}

	return fetchTokenResponse(config.tokenEndpoint, params);
}

async function refreshAccessToken(
	options: TokenRequestOptions,
): Promise<OAuth2TokenResponse> {
	const { config, refreshToken, additionalParams } = options;

	_validate.validateConfig(config);

	if (!refreshToken) {
		throw new OIDCError("Refresh token is required");
	}

	const params = new URLSearchParams();
	params.append("grant_type", GrantTypes.REFRESH_TOKEN);
	params.append("refresh_token", refreshToken);
	params.append("client_id", config.clientId);

	if (config.clientSecret) {
		const secret =
			typeof config.clientSecret === "function"
				? await config.clientSecret()
				: config.clientSecret;
		params.append("client_secret", secret);
	}

	if (config.additionalTokenParams) {
		for (const [key, value] of Object.entries(config.additionalTokenParams)) {
			params.append(key, value);
		}
	}

	if (additionalParams) {
		for (const [key, value] of Object.entries(additionalParams)) {
			params.append(key, value);
		}
	}

	return fetchTokenResponse(config.tokenEndpoint, params);
}

async function getClientCredentialsToken(
	options: TokenRequestOptions,
): Promise<OAuth2TokenResponse> {
	const { config, additionalParams } = options;

	_validate.validateConfig(config);

	if (!config.clientSecret) {
		throw new OIDCError(
			"Client secret is required for client credentials grant",
		);
	}

	const params = new URLSearchParams();
	params.append("grant_type", GrantTypes.CLIENT_CREDENTIALS);
	params.append("client_id", config.clientId);

	const secret =
		typeof config.clientSecret === "function"
			? await config.clientSecret()
			: config.clientSecret;
	params.append("client_secret", secret);

	if (config.defaultScopes && config.defaultScopes.length > 0) {
		params.append("scope", config.defaultScopes.join(" "));
	}

	if (config.additionalTokenParams) {
		for (const [key, value] of Object.entries(config.additionalTokenParams)) {
			params.append(key, value);
		}
	}

	if (additionalParams) {
		for (const [key, value] of Object.entries(additionalParams)) {
			params.append(key, value);
		}
	}

	return fetchTokenResponse(config.tokenEndpoint, params);
}

async function revokeToken(options: TokenRevocationOptions): Promise<void> {
	const { config, token, tokenTypeHint } = options;

	_validate.validateConfig(config);

	if (!config.revocationEndpoint) {
		throw new OIDCError(
			"Revocation endpoint is not configured for this provider",
		);
	}

	const params = new URLSearchParams();
	params.append("token", token);
	params.append("client_id", config.clientId);

	if (tokenTypeHint) {
		params.append("token_type_hint", tokenTypeHint);
	}

	if (config.clientSecret) {
		const secret =
			typeof config.clientSecret === "function"
				? await config.clientSecret()
				: config.clientSecret;
		params.append("client_secret", secret);
	}

	const response = await fetch(config.revocationEndpoint, {
		method: "POST",
		headers: {
			"Content-Type": "application/x-www-form-urlencoded",
			"User-Agent": "OAuth2-Client/1.0",
			"Cache-Control": "no-store",
		},
		body: params,
	});

	if (!response.ok) {
		const errorData = await response.json();
		throw new OIDCError(
			`Token revocation failed: ${errorData.error_description || errorData.error || response.statusText}`,
		);
	}
}

async function fetchTokenResponse(
	tokenEndpoint: string,
	params: URLSearchParams,
): Promise<OAuth2TokenResponse> {
	const maxRetries = 3;
	let attempts = 0;

	while (attempts <= maxRetries) {
		try {
			const response = await fetch(tokenEndpoint, {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Accept: "application/json",
					"User-Agent": "OAuth2-Client/1.0",
					"Cache-Control": "no-store",
				},
				body: params,
			});

			const data = await response.json();

			if (!response.ok) {
				const errorResponse = data as OAuth2ErrorResponse;
				throw new OIDCError(
					`OAuth2 error: ${errorResponse.error_description || errorResponse.error || response.statusText}`,
				);
			}

			const tokenResponse = data as OAuth2TokenResponse;
			if (!tokenResponse.access_token) {
				throw new OIDCError("Invalid token response: missing access_token");
			}
			if (!tokenResponse.token_type) {
				throw new OIDCError("Invalid token response: missing token_type");
			}
			if (
				tokenResponse.expires_in !== undefined &&
				tokenResponse.expires_in <= 0
			) {
				throw new OIDCError(
					"Invalid token response: expires_in must be positive",
				);
			}

			return tokenResponse;
		} catch (error) {
			attempts++;
			if (attempts > maxRetries) throw error;
			await new Promise((resolve) => setTimeout(resolve, 1000));
		}
	}
	throw new OIDCError("Unreachable code"); // TypeScript satisfaction
}

export const _util = {
	createRandomState: (length = 32): string => {
		const randomBytes = new Uint8Array(length);
		crypto.getRandomValues(randomBytes);
		return base64Url.encode(randomBytes);
	},
};
