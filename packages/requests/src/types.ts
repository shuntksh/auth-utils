export interface RateLimitPolicy {
	windowMs: number;
	maxRequests: number;
}

export interface RateLimitResponse {
	success: boolean;
	remaining: number;
	resetTime: number;
}

export interface StorageAdapter<T = unknown> {
	get(uid: string): Promise<T | undefined>;
	set(uid: string, value: T): Promise<void>;
	delete?(uid: string): Promise<boolean>;
	clear?(): Promise<void>;
}

export interface RequestEntry {
	timestamp: number; // Time of the request
	count: number; // Number of requests at this timestamp (for batching)
}

export type RateLimitStorage = StorageAdapter<RequestEntry[]>;
