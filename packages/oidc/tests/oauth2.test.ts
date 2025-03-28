import { beforeEach, describe, expect, mock, test } from "bun:test";

import { GrantTypes, OAuth2 } from "@auth-utils/oidc/oauth2";
import { PKCE } from "@auth-utils/oidc/pkce";
import { OAuth2Providers } from "@auth-utils/oidc/providers";

// Import the _util directly from the module for testing
import { _util } from "../src/oauth2";

// Mock fetch for testing
global.fetch = mock(async (url, options) => {
	if (url.toString().includes("token")) {
		// Mock token endpoint response
		return new Response(
			JSON.stringify({
				access_token: "mock_access_token",
				token_type: "Bearer",
				expires_in: 3600,
				refresh_token: "mock_refresh_token",
				scope: "openid profile email",
				id_token: "mock_id_token",
			}),
			{
				status: 200,
				headers: { "Content-Type": "application/json" },
			},
		);
	}

	if (url.toString().includes("revoke")) {
		// Mock revocation endpoint response
		return new Response(JSON.stringify({}), {
			status: 200,
			headers: { "Content-Type": "application/json" },
		});
	}

	return new Response(JSON.stringify({ error: "invalid_request" }), {
		status: 404,
		statusText: "Not Found",
		headers: { "Content-Type": "application/json" },
	});
}) as unknown as typeof fetch;

describe("OAuth2", () => {
	// Test provider configuration
	const testConfig = {
		provider: "test",
		authorizationEndpoint: "https://test.com/auth",
		tokenEndpoint: "https://test.com/token",
		revocationEndpoint: "https://test.com/revoke",
		clientId: "test_client_id",
		clientSecret: "test_client_secret",
		redirectUri: "https://app.com/callback",
		defaultScopes: ["profile", "email"],
		usePKCE: true,
	};

	// Test PKCE parameters
	let pkceParams: Awaited<ReturnType<typeof PKCE.generate>>;

	beforeEach(async () => {
		// Generate new PKCE parameters for each test
		pkceParams = await PKCE.generate();
	});

	test("createAuthorizationUrl - basic", () => {
		const url = OAuth2.createAuthorizationUrl({
			config: testConfig,
			state: "test_state",
		});

		expect(url).toContain(testConfig.authorizationEndpoint);
		expect(url).toContain(`client_id=${testConfig.clientId}`);
		expect(url).toContain(
			`redirect_uri=${encodeURIComponent(testConfig.redirectUri)}`,
		);
		expect(url).toContain("response_type=code");
		expect(url).toContain(`scope=${testConfig.defaultScopes.join("+")}`);
		expect(url).toContain("state=test_state");
	});

	test("createAuthorizationUrl - with PKCE", () => {
		const url = OAuth2.createAuthorizationUrl({
			config: testConfig,
			state: "test_state",
			pkce: pkceParams,
		});

		expect(url).toContain(
			`code_challenge=${encodeURIComponent(pkceParams.codeChallenge)}`,
		);
		expect(url).toContain(
			`code_challenge_method=${pkceParams.codeChallengeMethod}`,
		);
	});

	test("createAuthorizationUrl - with custom scopes", () => {
		const customScopes = ["custom_scope1", "custom_scope2"];
		const url = OAuth2.createAuthorizationUrl({
			config: testConfig,
			scopes: customScopes,
		});

		expect(url).toContain(`scope=${customScopes.join("+")}`);
		expect(url).not.toContain(
			encodeURIComponent(testConfig.defaultScopes.join(" ")),
		);
	});

	test("createAuthorizationUrl - with additional parameters", () => {
		const additionalParams = {
			prompt: "consent",
			access_type: "offline",
		};

		const url = OAuth2.createAuthorizationUrl({
			config: testConfig,
			additionalParams,
		});

		expect(url).toContain(`prompt=${additionalParams.prompt}`);
		expect(url).toContain(`access_type=${additionalParams.access_type}`);
	});

	test("exchangeCodeForTokens - success", async () => {
		const result = await OAuth2.exchangeCodeForTokens({
			config: testConfig,
			grantType: GrantTypes.AUTHORIZATION_CODE,
			code: "test_code",
			codeVerifier: pkceParams.codeVerifier,
		});

		expect(result).toHaveProperty("access_token", "mock_access_token");
		expect(result).toHaveProperty("token_type", "Bearer");
		expect(result).toHaveProperty("expires_in", 3600);
		expect(result).toHaveProperty("refresh_token", "mock_refresh_token");
		expect(result).toHaveProperty("id_token", "mock_id_token");
	});

	test("refreshAccessToken - success", async () => {
		const result = await OAuth2.refreshAccessToken({
			config: testConfig,
			grantType: GrantTypes.REFRESH_TOKEN,
			refreshToken: "test_refresh_token",
		});

		expect(result).toHaveProperty("access_token", "mock_access_token");
		expect(result).toHaveProperty("token_type", "Bearer");
	});

	test("getClientCredentialsToken - success", async () => {
		const result = await OAuth2.getClientCredentialsToken({
			config: testConfig,
			grantType: GrantTypes.CLIENT_CREDENTIALS,
		});

		expect(result).toHaveProperty("access_token", "mock_access_token");
		expect(result).toHaveProperty("token_type", "Bearer");
	});

	test("revokeToken - success", async () => {
		await expect(
			OAuth2.revokeToken({
				config: testConfig,
				token: "test_token",
				tokenTypeHint: "access_token",
			}),
		).resolves.toBeUndefined();
	});

	test("createRandomState - generates random state", () => {
		const state1 = _util.createRandomState();
		const state2 = _util.createRandomState();

		expect(state1).not.toEqual(state2);
		expect(state1.length).toBeGreaterThan(32);
		expect(state2.length).toBeGreaterThan(32);
	});

	describe("Provider configurations", () => {
		test("Google provider", () => {
			const googleConfig = OAuth2Providers.google({
				clientId: "google_client_id",
				clientSecret: "google_client_secret",
				redirectUri: "https://app.com/google/callback",
			});

			expect(googleConfig.provider).toBe("google");
			expect(googleConfig.authorizationEndpoint).toBe(
				"https://accounts.google.com/o/oauth2/v2/auth",
			);
			expect(googleConfig.tokenEndpoint).toBe(
				"https://oauth2.googleapis.com/token",
			);
			expect(googleConfig.revocationEndpoint).toBe(
				"https://oauth2.googleapis.com/revoke",
			);
			expect(googleConfig.clientId).toBe("google_client_id");
			expect(googleConfig.clientSecret).toBe("google_client_secret");
			expect(googleConfig.redirectUri).toBe("https://app.com/google/callback");
			expect(googleConfig.defaultScopes).toContain("openid");
			expect(googleConfig.defaultScopes).toContain("profile");
			expect(googleConfig.defaultScopes).toContain("email");
			expect(googleConfig.usePKCE).toBe(true);
			expect(googleConfig.additionalAuthParams).toHaveProperty(
				"access_type",
				"offline",
			);
			expect(googleConfig.additionalAuthParams).toHaveProperty(
				"prompt",
				"consent",
			);
		});

		test("GitHub provider", () => {
			const githubConfig = OAuth2Providers.github({
				clientId: "github_client_id",
				clientSecret: "github_client_secret",
				redirectUri: "https://app.com/github/callback",
			});

			expect(githubConfig.provider).toBe("github");
			expect(githubConfig.authorizationEndpoint).toBe(
				"https://github.com/login/oauth/authorize",
			);
			expect(githubConfig.tokenEndpoint).toBe(
				"https://github.com/login/oauth/access_token",
			);
			expect(githubConfig.revocationEndpoint).toContain(
				"https://github.com/settings/connections/applications/",
			);
			expect(githubConfig.clientId).toBe("github_client_id");
			expect(githubConfig.clientSecret).toBe("github_client_secret");
			expect(githubConfig.redirectUri).toBe("https://app.com/github/callback");
			expect(githubConfig.defaultScopes).toContain("user:email");
			expect(githubConfig.usePKCE).toBe(true);
		});

		test("Apple provider", () => {
			const appleConfig = OAuth2Providers.apple({
				clientId: "apple_client_id",
				clientSecret: "apple_client_secret",
				redirectUri: "https://app.com/apple/callback",
			});

			expect(appleConfig.provider).toBe("apple");
			expect(appleConfig.authorizationEndpoint).toBe(
				"https://appleid.apple.com/auth/authorize",
			);
			expect(appleConfig.tokenEndpoint).toBe(
				"https://appleid.apple.com/auth/token",
			);
			expect(appleConfig.revocationEndpoint).toBe(
				"https://appleid.apple.com/auth/revoke",
			);
			expect(appleConfig.clientId).toBe("apple_client_id");
			expect(appleConfig.clientSecret).toBe("apple_client_secret");
			expect(appleConfig.redirectUri).toBe("https://app.com/apple/callback");
			expect(appleConfig.defaultScopes).toContain("name");
			expect(appleConfig.defaultScopes).toContain("email");
			expect(appleConfig.usePKCE).toBe(true);
			expect(appleConfig.additionalAuthParams).toHaveProperty(
				"response_mode",
				"form_post",
			);
		});
	});
});
