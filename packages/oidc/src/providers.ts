/**
 * Provider-specific configurations for OAuth2 and OIDC
 *
 * This module contains pre-configured settings for popular OAuth2 and OIDC providers.
 * It separates provider-specific details from the core protocol implementations.
 */

import type { OAuth2ProviderConfig } from "./oauth2";
import type { OIDCProviderConfig } from "./oidc";

/**
 * OAuth2 provider configurations
 */
export const OAuth2Providers = {
	/**
	 * Google OAuth2 configuration
	 */
	google: (options: {
		clientId: string;
		clientSecret?: string | (() => string | Promise<string>);
		redirectUri: string;
		scopes?: string[];
	}): OAuth2ProviderConfig => ({
		provider: "google",
		authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
		tokenEndpoint: "https://oauth2.googleapis.com/token",
		revocationEndpoint: "https://oauth2.googleapis.com/revoke",
		clientId: options.clientId,
		clientSecret: options.clientSecret,
		redirectUri: options.redirectUri,
		defaultScopes: options.scopes || ["openid", "profile", "email"],
		usePKCE: true,
		additionalAuthParams: {
			access_type: "offline",
			prompt: "consent",
		},
	}),

	/**
	 * GitHub OAuth2 configuration
	 */
	github: (options: {
		clientId: string;
		clientSecret?: string | (() => string | Promise<string>);
		redirectUri: string;
		scopes?: string[];
	}): OAuth2ProviderConfig => ({
		provider: "github",
		authorizationEndpoint: "https://github.com/login/oauth/authorize",
		tokenEndpoint: "https://github.com/login/oauth/access_token",
		revocationEndpoint: "https://github.com/settings/connections/applications/",
		clientId: options.clientId,
		clientSecret: options.clientSecret,
		redirectUri: options.redirectUri,
		defaultScopes: options.scopes || ["user:email"],
		usePKCE: true,
	}),

	/**
	 * Apple OAuth2 configuration
	 */
	apple: (options: {
		clientId: string;
		clientSecret?: string | (() => string | Promise<string>);
		redirectUri: string;
		scopes?: string[];
	}): OAuth2ProviderConfig => ({
		provider: "apple",
		authorizationEndpoint: "https://appleid.apple.com/auth/authorize",
		tokenEndpoint: "https://appleid.apple.com/auth/token",
		revocationEndpoint: "https://appleid.apple.com/auth/revoke",
		clientId: options.clientId,
		clientSecret: options.clientSecret,
		redirectUri: options.redirectUri,
		defaultScopes: options.scopes || ["name", "email"],
		usePKCE: true,
		additionalAuthParams: {
			response_mode: "form_post",
		},
	}),
} as const;

/**
 * OIDC provider configurations
 */
export const OIDCProviders = {
	/**
	 * Google OIDC configuration
	 */
	google: (options: {
		clientId: string;
		clientSecret?: string | (() => string | Promise<string>);
		redirectUri: string;
		scopes?: string[];
	}): OIDCProviderConfig => ({
		...OAuth2Providers.google(options),
		issuer: "https://accounts.google.com",
		jwksUri: "https://www.googleapis.com/oauth2/v3/certs",
		userInfoEndpoint: "https://openidconnect.googleapis.com/v1/userinfo",
	}),

	/**
	 * GitHub OIDC configuration (GitHub doesn't fully support OIDC)
	 */
	github: (options: {
		clientId: string;
		clientSecret?: string | (() => string | Promise<string>);
		redirectUri: string;
		scopes?: string[];
	}): OIDCProviderConfig => ({
		...OAuth2Providers.github(options),
		issuer: "https://github.com",
		jwksUri: "", // GitHub doesn't provide JWKS
		userInfoEndpoint: "https://api.github.com/user",
	}),

	/**
	 * Apple OIDC configuration
	 */
	apple: (options: {
		clientId: string;
		clientSecret?: string | (() => string | Promise<string>);
		redirectUri: string;
		scopes?: string[];
	}): OIDCProviderConfig => ({
		...OAuth2Providers.apple(options),
		issuer: "https://appleid.apple.com",
		jwksUri: "https://appleid.apple.com/auth/keys",
		userInfoEndpoint: "", // Apple doesn't provide a userinfo endpoint
	}),
} as const;
