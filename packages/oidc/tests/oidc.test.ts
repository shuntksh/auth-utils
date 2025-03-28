// @cspell:disable
import { beforeEach, describe, expect, mock, test } from "bun:test";

import { OIDC } from "@auth-utils/oidc/oidc";
import { PKCE } from "@auth-utils/oidc/pkce";
import { OIDCProviders } from "@auth-utils/oidc/providers";

// Mock fetch for testing
global.fetch = mock(async (url, options) => {
	if (url.toString().includes("userinfo")) {
		// Mock userinfo endpoint response
		return new Response(
			JSON.stringify({
				sub: "123456789",
				name: "Test User",
				given_name: "Test",
				family_name: "User",
				email: "test@example.com",
				email_verified: true,
				picture: "https://example.com/profile.jpg",
			}),
			{
				status: 200,
				headers: { "Content-Type": "application/json" },
			},
		);
	}

	if (url.toString().includes("openid-configuration")) {
		// Mock discovery document
		return new Response(
			JSON.stringify({
				issuer: "https://test.com",
				authorization_endpoint: "https://test.com/auth",
				token_endpoint: "https://test.com/token",
				userinfo_endpoint: "https://test.com/userinfo",
				jwks_uri: "https://test.com/jwks",
				end_session_endpoint: "https://test.com/logout",
				response_types_supported: ["code", "token", "id_token"],
				subject_types_supported: ["public"],
				id_token_signing_alg_values_supported: ["RS256"],
			}),
			{
				status: 200,
				headers: { "Content-Type": "application/json" },
			},
		);
	}

	if (url.toString().includes("jwks")) {
		// Mock JWKS response
		return new Response(
			JSON.stringify({
				keys: [
					{
						kty: "RSA",
						kid: "test-key-id",
						use: "sig",
						alg: "RS256",
						n: "test-modulus",
						e: "AQAB",
					},
				],
			}),
			{
				status: 200,
				headers: { "Content-Type": "application/json" },
			},
		);
	}

	return new Response(JSON.stringify({ error: "invalid_request" }), {
		status: 404,
		statusText: "Not Found",
		headers: { "Content-Type": "application/json" },
	});
}) as unknown as typeof fetch;

// Create a mock for JWT.verify that we'll use with spyOn
const mockJWTVerify = mock(async () => ({
	valid: true,
	header: { alg: "RS256", kid: "test-key-id" },
	payload: {
		iss: "https://test.com",
		sub: "123456789",
		aud: "test_client_id",
		exp: Math.floor(Date.now() / 1000) + 3600,
		iat: Math.floor(Date.now() / 1000),
		nonce: "test_nonce",
		at_hash: "test_at_hash",
	},
}));

describe("OIDC", () => {
	// Test provider configuration
	const testConfig = {
		provider: "test",
		issuer: "https://test.com",
		authorizationEndpoint: "https://test.com/auth",
		tokenEndpoint: "https://test.com/token",
		userInfoEndpoint: "https://test.com/userinfo",
		jwksUri: "https://test.com/jwks",
		endSessionEndpoint: "https://test.com/logout",
		clientId: "test_client_id",
		clientSecret: "test_client_secret",
		redirectUri: "https://app.com/callback",
		defaultScopes: ["openid", "profile", "email"],
		usePKCE: true,
	};

	// Test PKCE parameters
	let pkceParams: Awaited<ReturnType<typeof PKCE.generate>>;

	beforeEach(async () => {
		// Generate new PKCE parameters for each test
		pkceParams = await PKCE.generate();
	});

	test("discover - fetches and parses OIDC configuration", async () => {
		const config = await OIDC.discover("https://test.com");

		expect(config.issuer).toBe("https://test.com");
		expect(config.authorizationEndpoint).toBe("https://test.com/auth");
		expect(config.tokenEndpoint).toBe("https://test.com/token");
		expect(config.userInfoEndpoint).toBe("https://test.com/userinfo");
		expect(config.jwksUri).toBe("https://test.com/jwks");
		expect(config.endSessionEndpoint).toBe("https://test.com/logout");
		expect(config.usePKCE).toBe(true);
	});

	test("createAuthenticationUrl - basic", () => {
		const url = OIDC.createAuthenticationUrl({
			config: testConfig,
			state: "test_state",
			nonce: "test_nonce",
		});

		expect(url).toContain(testConfig.authorizationEndpoint);
		expect(url).toContain(`client_id=${testConfig.clientId}`);
		expect(url).toContain(
			`redirect_uri=${encodeURIComponent(testConfig.redirectUri)}`,
		);
		expect(url).toContain("response_type=code");
		expect(url).toContain(`scope=${testConfig.defaultScopes.join("+")}`);
		expect(url).toContain("state=test_state");
		expect(url).toContain("nonce=test_nonce");
	});

	test("createAuthenticationUrl - with PKCE", () => {
		const url = OIDC.createAuthenticationUrl({
			config: testConfig,
			state: "test_state",
			nonce: "test_nonce",
			pkce: pkceParams,
		});

		expect(url).toContain(
			`code_challenge=${encodeURIComponent(pkceParams.codeChallenge)}`,
		);
		expect(url).toContain(
			`code_challenge_method=${pkceParams.codeChallengeMethod}`,
		);
	});

	test("createAuthenticationUrl - with additional parameters", () => {
		const url = OIDC.createAuthenticationUrl({
			config: testConfig,
			state: "test_state",
			nonce: "test_nonce",
			display: "popup",
			prompt: "login",
			maxAge: 3600,
			uiLocales: ["en-US", "fr-FR"],
			loginHint: "test@example.com",
		});

		expect(url).toContain("display=popup");
		expect(url).toContain("prompt=login");
		expect(url).toContain("max_age=3600");
		expect(url).toContain("ui_locales=en-US+fr-FR");
		expect(url).toContain(
			`login_hint=${encodeURIComponent("test@example.com")}`,
		);
	});

	test("fetchUserInfo - success", async () => {
		const userInfo = await OIDC.fetchUserInfo({
			config: testConfig,
			accessToken: "mock_access_token",
		});

		expect(userInfo).toHaveProperty("sub", "123456789");
		expect(userInfo).toHaveProperty("name", "Test User");
		expect(userInfo).toHaveProperty("email", "test@example.com");
		expect(userInfo).toHaveProperty("email_verified", true);
	});

	test("createLogoutUrl - basic", () => {
		const url = OIDC.createLogoutUrl({
			config: testConfig,
			idTokenHint: "mock_id_token",
			postLogoutRedirectUri: "https://app.com/logged-out",
			state: "test_state",
		});

		expect(url).toContain(testConfig.endSessionEndpoint);
		expect(url).toContain("id_token_hint=mock_id_token");
		expect(url).toContain(
			`post_logout_redirect_uri=${encodeURIComponent("https://app.com/logged-out")}`,
		);
		expect(url).toContain("state=test_state");
	});

	describe("Provider configurations", () => {
		test("Google provider", () => {
			const googleConfig = OIDCProviders.google({
				clientId: "google_client_id",
				clientSecret: "google_client_secret",
				redirectUri: "https://app.com/google/callback",
			});

			expect(googleConfig.provider).toBe("google");
			expect(googleConfig.issuer).toBe("https://accounts.google.com");
			expect(googleConfig.authorizationEndpoint).toBe(
				"https://accounts.google.com/o/oauth2/v2/auth",
			);
			expect(googleConfig.tokenEndpoint).toBe(
				"https://oauth2.googleapis.com/token",
			);
			expect(googleConfig.userInfoEndpoint).toBe(
				"https://openidconnect.googleapis.com/v1/userinfo",
			);
			expect(googleConfig.jwksUri).toBe(
				"https://www.googleapis.com/oauth2/v3/certs",
			);
			expect(googleConfig.clientId).toBe("google_client_id");
			expect(googleConfig.clientSecret).toBe("google_client_secret");
			expect(googleConfig.redirectUri).toBe("https://app.com/google/callback");
			expect(googleConfig.defaultScopes).toContain("openid");
			expect(googleConfig.defaultScopes).toContain("profile");
			expect(googleConfig.defaultScopes).toContain("email");
			expect(googleConfig.usePKCE).toBe(true);
		});

		test("Apple provider", () => {
			const appleConfig = OIDCProviders.apple({
				clientId: "apple_client_id",
				clientSecret: "apple_client_secret",
				redirectUri: "https://app.com/apple/callback",
			});

			expect(appleConfig.provider).toBe("apple");
			expect(appleConfig.issuer).toBe("https://appleid.apple.com");
			expect(appleConfig.authorizationEndpoint).toBe(
				"https://appleid.apple.com/auth/authorize",
			);
			expect(appleConfig.tokenEndpoint).toBe(
				"https://appleid.apple.com/auth/token",
			);
			expect(appleConfig.jwksUri).toBe("https://appleid.apple.com/auth/keys");
			expect(appleConfig.clientId).toBe("apple_client_id");
			expect(appleConfig.clientSecret).toBe("apple_client_secret");
			expect(appleConfig.redirectUri).toBe("https://app.com/apple/callback");
			expect(appleConfig.defaultScopes).toContain("name");
			expect(appleConfig.defaultScopes).toContain("email");
			expect(appleConfig.usePKCE).toBe(true);
		});
	});

	// No need for separate setup/teardown hooks as we're handling mocking within each test
});
