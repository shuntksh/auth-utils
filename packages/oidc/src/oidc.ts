/**
 * OpenID Connect (OIDC) implementation
 *
 * This module provides functionality for OpenID Connect authentication:
 * - Discovery of OIDC provider configuration
 * - Authentication using the authorization code flow
 * - ID token validation
 * - User info retrieval
 *
 * It builds on top of the OAuth2 module and adds OIDC-specific functionality.
 * Provider-specific configurations have been moved to the providers.ts module.
 */

import type { JWKKeySet, StandardClaims, VerifyResult } from "./deps";
import { base64Url, JWT, OIDCError } from "./deps";
import {
	OAuth2,
	type OAuth2ProviderConfig,
	type OAuth2TokenResponse,
} from "./oauth2";
import type { PKCEParams } from "./pkce";

/**
 * OIDC Provider Configuration
 * Extends OAuth2ProviderConfig with OIDC-specific endpoints and parameters
 */
export interface OIDCProviderConfig extends OAuth2ProviderConfig {
	/**
	 * OIDC issuer URL
	 */
	issuer: string;

	/**
	 * JWKS URI for retrieving the provider's public keys
	 */
	jwksUri: string;

	/**
	 * User info endpoint URL
	 */
	userInfoEndpoint: string;

	/**
	 * End session endpoint URL (optional)
	 */
	endSessionEndpoint?: string;

	/**
	 * Registration endpoint URL (optional)
	 */
	registrationEndpoint?: string;
}

/**
 * OIDC Discovery Document
 * As defined in OpenID Connect Discovery 1.0
 */
export interface OIDCDiscoveryDocument {
	issuer: string;
	authorization_endpoint: string;
	token_endpoint: string;
	userinfo_endpoint: string;
	jwks_uri: string;
	registration_endpoint?: string;
	scopes_supported?: string[];
	response_types_supported: string[];
	response_modes_supported?: string[];
	grant_types_supported?: string[];
	subject_types_supported: string[];
	id_token_signing_alg_values_supported: string[];
	id_token_encryption_alg_values_supported?: string[];
	id_token_encryption_enc_values_supported?: string[];
	userinfo_signing_alg_values_supported?: string[];
	userinfo_encryption_alg_values_supported?: string[];
	userinfo_encryption_enc_values_supported?: string[];
	request_object_signing_alg_values_supported?: string[];
	request_object_encryption_alg_values_supported?: string[];
	request_object_encryption_enc_values_supported?: string[];
	token_endpoint_auth_methods_supported?: string[];
	token_endpoint_auth_signing_alg_values_supported?: string[];
	display_values_supported?: string[];
	claim_types_supported?: string[];
	claims_supported?: string[];
	service_documentation?: string;
	claims_locales_supported?: string[];
	ui_locales_supported?: string[];
	claims_parameter_supported?: boolean;
	request_parameter_supported?: boolean;
	request_uri_parameter_supported?: boolean;
	require_request_uri_registration?: boolean;
	op_policy_uri?: string;
	op_tos_uri?: string;
	end_session_endpoint?: string;
	revocation_endpoint?: string;
	[key: string]: unknown;
}

/**
 * OIDC ID Token Claims
 * As defined in OpenID Connect Core 1.0
 */
export interface IDTokenClaims extends StandardClaims {
	/**
	 * Nonce value used to mitigate replay attacks
	 */
	nonce?: string;

	/**
	 * Authentication time
	 */
	auth_time?: number;

	/**
	 * Access token hash
	 */
	at_hash?: string;

	/**
	 * Code hash
	 */
	c_hash?: string;

	/**
	 * Authentication context class reference
	 */
	acr?: string;

	/**
	 * Authentication methods references
	 */
	amr?: string[];

	/**
	 * Authorized party
	 */
	azp?: string;
}

/**
 * OIDC User Info
 * As defined in OpenID Connect Core 1.0
 */
export interface UserInfo {
	/**
	 * Subject identifier
	 */
	sub: string;

	/**
	 * Full name
	 */
	name?: string;

	/**
	 * Given name
	 */
	given_name?: string;

	/**
	 * Family name
	 */
	family_name?: string;

	/**
	 * Middle name
	 */
	middle_name?: string;

	/**
	 * Nickname
	 */
	nickname?: string;

	/**
	 * Preferred username
	 */
	preferred_username?: string;

	/**
	 * Profile URL
	 */
	profile?: string;

	/**
	 * Picture URL
	 */
	picture?: string;

	/**
	 * Website URL
	 */
	website?: string;

	/**
	 * Email address
	 */
	email?: string;

	/**
	 * Email verified
	 */
	email_verified?: boolean;

	/**
	 * Gender
	 */
	gender?: string;

	/**
	 * Birthday
	 */
	birthdate?: string;

	/**
	 * Time zone
	 */
	zoneinfo?: string;

	/**
	 * Locale
	 */
	locale?: string;

	/**
	 * Phone number
	 */
	phone_number?: string;

	/**
	 * Phone number verified
	 */
	phone_number_verified?: boolean;

	/**
	 * Address
	 */
	address?: {
		formatted?: string;
		street_address?: string;
		locality?: string;
		region?: string;
		postal_code?: string;
		country?: string;
	};

	/**
	 * Updated at
	 */
	updated_at?: number;

	/**
	 * Additional claims
	 */
	[key: string]: unknown;
}

/**
 * OIDC Authentication Request Options
 */
export interface OIDCAuthenticationRequestOptions {
	/**
	 * Provider configuration
	 */
	config: OIDCProviderConfig;

	/**
	 * Redirect URI
	 */
	redirectUri?: string;

	/**
	 * Scopes to request
	 */
	scopes?: string[];

	/**
	 * State parameter for CSRF protection
	 */
	state?: string;

	/**
	 * Nonce parameter for replay protection
	 */
	nonce?: string;

	/**
	 * PKCE parameters
	 */
	pkce?: PKCEParams;

	/**
	 * Display parameter
	 */
	display?: "page" | "popup" | "touch" | "wap";

	/**
	 * Prompt parameter
	 */
	prompt?: "none" | "login" | "consent" | "select_account";

	/**
	 * Maximum authentication age in seconds
	 */
	maxAge?: number;

	/**
	 * UI locales
	 */
	uiLocales?: string[];

	/**
	 * ID token hint
	 */
	idTokenHint?: string;

	/**
	 * Login hint
	 */
	loginHint?: string;

	/**
	 * ACR values
	 */
	acrValues?: string[];

	/**
	 * Additional parameters
	 */
	additionalParams?: Record<string, string>;
}

/**
 * OIDC Token Validation Options
 */
export interface OIDCTokenValidationOptions {
	/**
	 * ID token to validate
	 */
	idToken: string;

	/**
	 * Provider configuration
	 */
	config: OIDCProviderConfig;

	/**
	 * JWKS for token validation
	 */
	jwks?: JWKKeySet;

	/**
	 * Nonce value used in the authentication request
	 */
	nonce?: string;

	/**
	 * Access token for at_hash validation
	 */
	accessToken?: string;

	/**
	 * Authorization code for c_hash validation
	 */
	code?: string;

	/**
	 * Maximum authentication age in seconds
	 */
	maxAge?: number;

	/**
	 * Clock tolerance in seconds
	 */
	clockTolerance?: number;
}

/**
 * OIDC Client
 */
export const OIDC = {
	/**
	 * Discovers OIDC provider configuration
	 */
	discover,

	/**
	 * Creates an authentication URL for the OIDC authorization code flow
	 */
	createAuthenticationUrl,

	/**
	 * Handles the authentication response
	 */
	handleAuthenticationResponse,

	/**
	 * Validates an ID token
	 */
	validateIdToken,

	/**
	 * Fetches user info
	 */
	fetchUserInfo,

	/**
	 * Creates a logout URL
	 */
	createLogoutUrl,
} as const;

/**
 * Discovers OIDC provider configuration from a well-known endpoint
 *
 * @param issuerUrl - The issuer URL
 * @returns Promise resolving to the OIDC provider configuration
 */
async function discover(issuerUrl: string): Promise<OIDCProviderConfig> {
	// Ensure the issuer URL doesn't have a trailing slash
	const normalizedIssuerUrl = issuerUrl.endsWith("/")
		? issuerUrl.slice(0, -1)
		: issuerUrl;

	// Fetch the discovery document from the well-known endpoint
	const discoveryUrl = `${normalizedIssuerUrl}/.well-known/openid-configuration`;
	const response = await fetch(discoveryUrl);

	if (!response.ok) {
		throw new OIDCError(
			`Failed to discover OIDC configuration: ${response.statusText}`,
		);
	}

	const discoveryDocument = (await response.json()) as OIDCDiscoveryDocument;

	// Validate the discovery document
	if (discoveryDocument.issuer !== normalizedIssuerUrl) {
		throw new OIDCError(
			`Issuer mismatch: expected ${normalizedIssuerUrl}, got ${discoveryDocument.issuer}`,
		);
	}

	// Convert the discovery document to an OIDC provider configuration
	return {
		provider: new URL(normalizedIssuerUrl).hostname,
		issuer: discoveryDocument.issuer,
		authorizationEndpoint: discoveryDocument.authorization_endpoint,
		tokenEndpoint: discoveryDocument.token_endpoint,
		userInfoEndpoint: discoveryDocument.userinfo_endpoint,
		jwksUri: discoveryDocument.jwks_uri,
		revocationEndpoint: discoveryDocument.revocation_endpoint,
		endSessionEndpoint: discoveryDocument.end_session_endpoint,
		registrationEndpoint: discoveryDocument.registration_endpoint,
		clientId: "", // Must be provided by the caller
		redirectUri: "", // Must be provided by the caller
		usePKCE: true,
	};
}

/**
 * Creates an authentication URL for the OIDC authorization code flow
 *
 * @param options - Authentication request options
 * @returns The authentication URL
 */
function createAuthenticationUrl(
	options: OIDCAuthenticationRequestOptions,
): string {
	const {
		config,
		redirectUri,
		scopes,
		state,
		nonce,
		pkce,
		display,
		prompt,
		maxAge,
		uiLocales,
		idTokenHint,
		loginHint,
		acrValues,
		additionalParams,
	} = options;

	// Ensure openid scope is included
	const scopeList = scopes || config.defaultScopes || [];
	if (!scopeList.includes("openid")) {
		scopeList.unshift("openid");
	}

	// Build additional parameters
	const params: Record<string, string> = {};

	if (nonce) {
		params.nonce = nonce;
	}

	if (display) {
		params.display = display;
	}

	if (prompt) {
		params.prompt = prompt;
	}

	if (maxAge !== undefined) {
		params.max_age = maxAge.toString();
	}

	if (uiLocales && uiLocales.length > 0) {
		params.ui_locales = uiLocales.join(" ");
	}

	if (idTokenHint) {
		params.id_token_hint = idTokenHint;
	}

	if (loginHint) {
		params.login_hint = loginHint;
	}

	if (acrValues && acrValues.length > 0) {
		params.acr_values = acrValues.join(" ");
	}

	// Merge with additional parameters
	const mergedParams = { ...params, ...additionalParams };

	// Create the authorization URL using OAuth2
	return OAuth2.createAuthorizationUrl({
		config,
		scopes: scopeList,
		state,
		pkce,
		additionalParams: mergedParams,
		...(redirectUri ? { config: { ...config, redirectUri } } : {}),
	});
}

/**
 * Handles the authentication response from the OIDC provider
 *
 * @param options - Options for handling the authentication response
 * @returns Promise resolving to the token response and validated ID token claims
 */
async function handleAuthenticationResponse(options: {
	config: OIDCProviderConfig;
	code: string;
	codeVerifier?: string;
	state?: string;
	expectedState?: string;
	nonce?: string;
	jwks?: JWKKeySet;
}): Promise<{
	tokens: OAuth2TokenResponse;
	idTokenClaims?: IDTokenClaims;
}> {
	const { config, code, codeVerifier, state, expectedState, nonce, jwks } =
		options;

	// Verify state if provided
	if (expectedState && state !== expectedState) {
		throw new OIDCError("State mismatch");
	}

	// Exchange the authorization code for tokens
	const tokens = await OAuth2.exchangeCodeForTokens({
		config,
		grantType: "authorization_code",
		code,
		codeVerifier,
	});

	// Validate the ID token if present
	let idTokenClaims: IDTokenClaims | undefined;
	if (tokens.id_token) {
		const validationResult = await validateIdToken({
			idToken: tokens.id_token,
			config,
			jwks,
			nonce,
			accessToken: tokens.access_token,
			code,
		});

		if (!validationResult.valid) {
			throw new OIDCError(
				`ID token validation failed: ${validationResult.error}`,
			);
		}

		idTokenClaims = validationResult.payload as IDTokenClaims;
	}

	return { tokens, idTokenClaims };
}

/**
 * Validates an ID token
 *
 * @param options - Token validation options
 * @returns Promise resolving to the verification result
 */
async function validateIdToken(
	options: OIDCTokenValidationOptions,
): Promise<VerifyResult> {
	const {
		idToken,
		config,
		jwks,
		nonce,
		accessToken,
		code,
		maxAge,
		clockTolerance = 0,
	} = options;

	// Fetch JWKS if not provided
	const keySet = jwks || (await fetchJwks(config.jwksUri));

	// Verify the ID token signature and basic claims
	const verifyResult = await JWT.verify({
		token: idToken,
		key: keySet,
		issuer: config.issuer,
		audience: config.clientId,
		clockTolerance,
	});

	if (!verifyResult.valid) {
		return verifyResult;
	}

	const claims = verifyResult.payload as IDTokenClaims;

	// Verify nonce if provided
	if (nonce && claims.nonce !== nonce) {
		return {
			valid: false,
			header: verifyResult.header,
			payload: claims,
			error: "Nonce mismatch",
		};
	}

	// Verify access token hash if access token is provided
	if (accessToken && claims.at_hash) {
		const validAtHash = await verifyTokenHash({
			hash: claims.at_hash,
			token: accessToken,
			alg: verifyResult.header.alg,
		});

		if (!validAtHash) {
			return {
				valid: false,
				header: verifyResult.header,
				payload: claims,
				error: "Access token hash mismatch",
			};
		}
	}

	// Verify code hash if code is provided
	if (code && claims.c_hash) {
		const validCHash = await verifyTokenHash({
			hash: claims.c_hash,
			token: code,
			alg: verifyResult.header.alg,
		});

		if (!validCHash) {
			return {
				valid: false,
				header: verifyResult.header,
				payload: claims,
				error: "Code hash mismatch",
			};
		}
	}

	// Verify auth_time if maxAge is provided
	if (
		maxAge !== undefined &&
		claims.auth_time !== undefined &&
		Math.floor(Date.now() / 1000) - claims.auth_time > maxAge + clockTolerance
	) {
		return {
			valid: false,
			header: verifyResult.header,
			payload: claims,
			error: "Authentication too old",
		};
	}

	return verifyResult;
}

/**
 * Fetches user info from the OIDC provider
 *
 * @param options - Options for fetching user info
 * @returns Promise resolving to the user info
 */
async function fetchUserInfo(options: {
	config: OIDCProviderConfig;
	accessToken: string;
}): Promise<UserInfo> {
	const { config, accessToken } = options;

	if (!config.userInfoEndpoint) {
		throw new OIDCError("User info endpoint not configured");
	}

	const response = await fetch(config.userInfoEndpoint, {
		method: "GET",
		headers: {
			Authorization: `Bearer ${accessToken}`,
		},
	});

	if (!response.ok) {
		throw new OIDCError(`Failed to fetch user info: ${response.statusText}`);
	}

	return response.json() as Promise<UserInfo>;
}

/**
 * Creates a logout URL for the OIDC provider
 *
 * @param options - Options for creating the logout URL
 * @returns The logout URL
 */
function createLogoutUrl(options: {
	config: OIDCProviderConfig;
	idTokenHint?: string;
	postLogoutRedirectUri?: string;
	state?: string;
}): string {
	const { config, idTokenHint, postLogoutRedirectUri, state } = options;

	if (!config.endSessionEndpoint) {
		throw new OIDCError("End session endpoint not configured");
	}

	const url = new URL(config.endSessionEndpoint);

	if (idTokenHint) {
		url.searchParams.append("id_token_hint", idTokenHint);
	}

	if (postLogoutRedirectUri) {
		url.searchParams.append("post_logout_redirect_uri", postLogoutRedirectUri);
	}

	if (state) {
		url.searchParams.append("state", state);
	}

	return url.toString();
}

/**
 * Fetches JWKS from the JWKS URI
 *
 * @param jwksUri - The JWKS URI
 * @returns Promise resolving to the JWK Set
 */
async function fetchJwks(jwksUri: string): Promise<JWKKeySet> {
	const response = await fetch(jwksUri);

	if (!response.ok) {
		throw new OIDCError(`Failed to fetch JWKS: ${response.statusText}`);
	}

	return response.json() as Promise<JWKKeySet>;
}

/**
 * Verifies a token hash (at_hash or c_hash)
 *
 * @param options - Options for verifying the token hash
 * @returns Promise resolving to a boolean indicating whether the hash is valid
 */
async function verifyTokenHash(options: {
	hash: string;
	token: string;
	alg: string;
}): Promise<boolean> {
	const { hash, token, alg } = options;

	// Determine the hash algorithm based on the JWS algorithm
	let hashAlg: string;
	if (alg === "HS256" || alg === "RS256" || alg === "ES256") {
		hashAlg = "SHA-256";
	} else if (alg === "HS384" || alg === "RS384" || alg === "ES384") {
		hashAlg = "SHA-384";
	} else if (alg === "HS512" || alg === "RS512" || alg === "ES512") {
		hashAlg = "SHA-512";
	} else {
		throw new OIDCError(`Unsupported algorithm: ${alg}`);
	}

	// Hash the token
	const encoder = new TextEncoder();
	const data = encoder.encode(token);
	const hashBuffer = await crypto.subtle.digest(hashAlg, data);

	// Take the left half of the hash
	const hashArray = new Uint8Array(hashBuffer);
	const leftHalf = hashArray.slice(0, hashArray.length / 2);

	// Base64url encode the left half
	const calculatedHash = base64Url.encode(leftHalf);

	// Compare the calculated hash with the provided hash
	return calculatedHash === hash;
}

/**
 * Utility functions for OIDC
 */
export const _util = {
	fetchJwks,
	verifyTokenHash,
};
