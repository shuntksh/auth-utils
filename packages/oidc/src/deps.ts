export { JWT } from "@auth-utils/jwt";
export type {
	JWKKeySet,
	StandardClaims,
	VerifyResult,
} from "@auth-utils/jwt";
export { base64Url } from "@auth-utils/shared/encoding";
export { constantTimeEqual } from "@auth-utils/shared/equal";

export class OIDCError extends Error {
	type = "oidc";
}
