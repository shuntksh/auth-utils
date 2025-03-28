export { constantTimeEqual } from "@auth-utils/shared/equal";

export class RequestError extends Error {
	readonly type = "request";
}
