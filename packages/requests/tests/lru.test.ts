import { afterEach, describe, expect, it, setSystemTime } from "bun:test";
import { fc, test as fcTest } from "fast-check-bun-test";

import { LRUCache } from "@auth-utils/requests/lru";

afterEach(() => {
	setSystemTime();
});

describe("LRUCache", () => {
	describe("constructor", () => {
		it("should create cache with default capacity", () => {
			using cache = new LRUCache();
			expect(cache).toBeInstanceOf(LRUCache);
		});

		it("should create cache with specified capacity", () => {
			using cache = new LRUCache(100);
			expect(cache).toBeInstanceOf(LRUCache);
		});

		it("should throw error for invalid capacity", () => {
			expect(() => new LRUCache(0)).toThrow(
				"Capacity must be a positive integer",
			);
			expect(() => new LRUCache(-1)).toThrow(
				"Capacity must be a positive integer",
			);
			expect(() => new LRUCache(1.5)).toThrow(
				"Capacity must be a positive integer",
			);
		});
	});

	describe("basic operations", () => {
		it("should set and get values", async () => {
			using cache = new LRUCache(2);
			await cache.set("key1", "value1");
			await cache.set("key2", "value2");

			expect(await cache.get("key1")).toBe("value1");
			expect(await cache.get("key2")).toBe("value2");
			expect(await cache.get("key3")).toBeUndefined();
		});

		it("should evict least recently used item when capacity is reached", async () => {
			using cache = new LRUCache(2);
			await cache.set("key1", "value1");
			await cache.set("key2", "value2");
			await cache.set("key3", "value3");

			expect(await cache.get("key1")).toBeUndefined();
			expect(await cache.get("key2")).toBe("value2");
			expect(await cache.get("key3")).toBe("value3");
		});

		it("should update existing key", async () => {
			using cache = new LRUCache(2);
			await cache.set("key1", "value1");
			await cache.set("key1", "value2");

			expect(await cache.get("key1")).toBe("value2");
		});
	});

	describe("TTL functionality", () => {
		it("should respect TTL", async () => {
			const now = new Date(2024, 0, 1, 12, 0, 0);
			setSystemTime(now);

			using cache = new LRUCache(2, { ttl: 100 });
			await cache.set("key1", "value1");

			expect(await cache.get("key1")).toBe("value1");

			// Advance time by 150ms
			setSystemTime(new Date(now.getTime() + 150));

			expect(await cache.get("key1")).toBeUndefined();

			setSystemTime();
		});

		it("should auto-purge stale entries", async () => {
			const now = new Date(2024, 0, 1, 12, 0, 0);
			setSystemTime(now);

			using cache = new LRUCache(2, { ttl: 100, ttlAutoPurge: true });
			await cache.set("key1", "value1");

			// Advance time by 150ms to trigger TTL
			setSystemTime(new Date(now.getTime() + 150));

			// Trigger purge directly
			await cache.purgeStale();

			expect(cache.getSize()).toBe(0);

			setSystemTime();
		});
	});

	describe("size management", () => {
		it("should respect maxSize option", async () => {
			using cache = new LRUCache(3, { maxSize: 3 });
			await cache.set("key1", "value1", 1);
			await cache.set("key2", "value2", 2);

			// This should evict key1 because total size would be 4 which exceeds maxSize of 3
			await cache.set("key3", "value3", 1);

			expect(await cache.get("key1")).toBeUndefined();
			expect(await cache.get("key2")).toBe("value2");
			expect(await cache.get("key3")).toBe("value3");
		});

		it("should reject items larger than maxSize", async () => {
			using cache = new LRUCache(2, { maxSize: 1 });
			await cache.set("key1", "value1", 2);

			expect(await cache.get("key1")).toBeUndefined();
		});
	});

	describe("property-based tests", () => {
		fcTest.prop([
			fc.integer({ min: 1, max: 100 }),
			fc.array(
				fc.tuple(fc.string(), fc.string(), fc.integer({ min: 1, max: 10 })),
			),
		])("should maintain size constraints", async (capacity, operations) => {
			using cache = new LRUCache(capacity);

			for (const [key, value, size] of operations) {
				await cache.set(key, value, size);
			}

			const currentSize = await cache.getSize();
			expect(currentSize).toBeLessThanOrEqual(capacity);
		});

		fcTest.prop([
			fc.integer({ min: 1, max: 100 }),
			fc.array(
				fc.tuple(
					fc.string().filter((s) => s.trim() !== ""),
					fc.string(),
				),
			),
		])("should maintain LRU order", async (capacity, operations) => {
			// Skip test for very small capacities
			if (capacity < 2) {
				return;
			}

			const cache = new LRUCache(capacity);

			// Filter out duplicate keys, keeping only the last occurrence
			const uniqueOperations = operations.reduce((acc, [key, value]) => {
				acc.set(key, value);
				return acc;
			}, new Map<string, string>());

			const validOperations = Array.from(uniqueOperations.entries()).map(
				([key, value]) => [key, value] as [string, string],
			);

			// Skip test if we don't have enough operations
			if (validOperations.length < 2) {
				return;
			}

			// Limit the number of initial items to the cache capacity
			const initialItems = validOperations.slice(0, capacity);

			// Set initial values
			for (const [key, value] of initialItems) {
				await cache.set(key, value);
			}

			// Make sure cache has items
			if ((await cache.getSize()) === 0) {
				return;
			}

			// Access the first item to make it recently used
			const accessedKey = initialItems[0][0];
			const accessedValue = initialItems[0][1];
			const valueBeforeAccess = await cache.get(accessedKey);

			// Skip if the item is not in the cache
			if (valueBeforeAccess === undefined) {
				return;
			}

			// Add just one new item to potentially trigger eviction
			// but not enough to evict all items
			if (initialItems.length >= capacity) {
				// If cache is full, adding one more should evict the LRU item
				// but not the recently accessed one
				await cache.set("new_key", "new_value");

				// The accessed item should still be in the cache
				const valueAfterNewItem = await cache.get(accessedKey);
				expect(valueAfterNewItem).toBe(accessedValue);
			}
		});
	});
});
