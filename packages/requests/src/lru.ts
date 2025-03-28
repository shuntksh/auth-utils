import { RequestError } from "./deps";
import type { StorageAdapter } from "./types";

const typeSymbol = Symbol("type");

/**
 * Branded type for milliseconds to ensure type safety
 */
type Milliseconds = number & { [typeSymbol]: "Milliseconds" };

/**
 * Branded type for positive integers to ensure type safety
 */
type PositiveInt = number & { [typeSymbol]: "PositiveInt" };

/**
 * Type guard to ensure a number is a positive integer
 */
const isPositiveInt = (n: number): n is PositiveInt =>
	Number.isInteger(n) && n > 0 && Number.isFinite(n);

/**
 * Node class representing an entry in the LRU cache
 * Each node contains the key-value pair, pointers to previous and next nodes,
 * a timestamp for TTL calculations, and an optional size for memory management
 */
class Node<T> {
	key: string;
	value: T;
	prev: number; // Index of previous node in the linked list
	next: number; // Index of next node in the linked list
	timestamp: number; // Used for TTL calculations
	size?: number; // Optional size for memory-aware caching

	constructor(key: string, value: T) {
		this.key = key;
		this.value = value;
		this.prev = 0;
		this.next = 0;
		this.timestamp = Date.now();
	}
}

/**
 * LRUCache - A high-performance Least Recently Used (LRU) cache implementation
 *
 * This cache implements the StorageAdapter interface and provides an efficient way to
 * store and retrieve data with automatic eviction of least recently used items when
 * capacity is reached. It supports both count-based and size-based limits, as well as
 * time-to-live (TTL) functionality.
 *
 * Key features:
 * - Fixed capacity limit (number of items)
 * - Optional maximum size limit (sum of item sizes)
 * - Optional TTL (time-to-live) for cache entries
 * - Automatic purging of stale entries
 * - Thread-safe operations via async locking mechanism
 * - Memory-efficient implementation using arrays for linked list
 *
 * Implementation details:
 * - Uses a doubly-linked list for O(1) access and updates
 * - Stores nodes in pre-allocated arrays for better memory efficiency
 * - Maintains separate arrays for next/prev pointers instead of object references
 * - Uses a Map for O(1) key-to-index lookups
 * - Implements the disposable pattern for cleanup
 *
 * Usage example:
 * ```
 * using cache = new LRUCache<string>(100, {
 *   maxSize: 1000000,
 *   ttl: 60000, // 1 minute
 *   ttlAutoPurge: true
 * });
 *
 * await cache.set("key1", "value1");
 * const value = await cache.get("key1");
 * ```
 */
export class LRUCache<T> implements StorageAdapter<T> {
	// Configuration properties
	private capacity: PositiveInt; // Maximum number of items in the cache
	private maxSize: PositiveInt; // Maximum total size of all items (optional)

	// Core data structures
	private cache: Map<string, number>; // Maps keys to node indices for O(1) lookup
	private nodes: (Node<T> | undefined)[]; // Array of nodes (or undefined for free slots)

	// Linked list implementation using arrays instead of object references
	private next: Uint32Array; // Array of next pointers (indices)
	private prev: Uint32Array; // Array of previous pointers (indices)
	private head: number; // Index of the most recently used item
	private tail: number; // Index of the least recently used item

	// Memory management
	private free: number[]; // Stack of available indices in the nodes array
	private currentSize: number; // Current number of items in the cache
	private totalSize: number; // Current total size of all items

	// TTL (Time-To-Live) functionality
	private ttl?: Milliseconds; // Optional TTL for cache entries
	private ttlResolution: Milliseconds; // How often to check for stale entries
	private ttlAutoPurge: boolean; // Whether to automatically purge stale entries

	// Concurrency control
	private isLocked = false; // Whether the cache is currently locked
	private lockQueue: (() => void)[] = []; // Queue of functions waiting for the lock
	private purgeInterval?: ReturnType<typeof setInterval>; // Interval for purging stale entries

	/**
	 * Creates a new LRUCache instance
	 *
	 * @param capacity Maximum number of items in the cache (default: 1000)
	 * @param options Configuration options
	 * @param options.maxSize Maximum total size of all items (optional)
	 * @param options.ttl Time-to-live in milliseconds for cache entries (optional)
	 * @param options.ttlResolution How often to check for stale entries (default: 1000ms)
	 * @param options.ttlAutoPurge Whether to automatically purge stale entries (default: false)
	 */
	constructor(
		capacity = 1000,
		options: {
			maxSize?: number;
			ttl?: number;
			ttlResolution?: number;
			ttlAutoPurge?: boolean;
		} = {},
	) {
		if (!isPositiveInt(capacity)) {
			throw new RequestError("Capacity must be a positive integer");
		}
		if (options.maxSize !== undefined && !isPositiveInt(options.maxSize)) {
			throw new RequestError("maxSize must be a positive integer");
		}
		if (options.ttl !== undefined && !isPositiveInt(options.ttl)) {
			throw new RequestError("ttl must be a positive integer");
		}
		if (
			options.ttlResolution !== undefined &&
			!isPositiveInt(options.ttlResolution)
		) {
			throw new RequestError("ttlResolution must be a positive integer");
		}

		this.capacity = capacity as PositiveInt;
		this.maxSize = (options.maxSize ?? Number.MAX_SAFE_INTEGER) as PositiveInt;
		this.cache = new Map();
		this.nodes = new Array(capacity);
		this.next = new Uint32Array(capacity);
		this.prev = new Uint32Array(capacity);
		this.head = 0;
		this.tail = 0;
		this.free = Array.from({ length: capacity }, (_, i) => i);
		this.currentSize = 0;
		this.totalSize = 0;
		this.ttl = options.ttl as Milliseconds | undefined;
		this.ttlResolution = (options.ttlResolution ?? 1000) as Milliseconds;
		this.ttlAutoPurge = !!options.ttlAutoPurge;

		// Set up automatic purging of stale entries if TTL and autoPurge are enabled
		if (this.ttl && this.ttlAutoPurge) {
			this.purgeInterval = setInterval(
				() => this.purgeStale(),
				this.ttlResolution,
			);
		}
	}

	/**
	 * Implements the disposable pattern to clean up resources
	 * Clears the purge interval when the cache is disposed
	 */
	[Symbol.dispose](): void {
		if (this.purgeInterval) {
			clearInterval(this.purgeInterval);
		}
	}

	/**
	 * Checks if a cache entry is stale based on its timestamp and the TTL
	 *
	 * @param index Index of the node to check
	 * @returns True if the entry is stale, false otherwise
	 */
	private isStale(index: number): boolean {
		if (!this.ttl) return false;
		const node = this.nodes[index];
		if (!node) return false;
		return Date.now() - node.timestamp > this.ttl;
	}

	/**
	 * Acquires a lock on the cache to ensure thread safety
	 * If the cache is already locked, the caller will be queued
	 */
	private async lock(): Promise<void> {
		if (this.isLocked) {
			return new Promise((resolve) => this.lockQueue.push(resolve));
		}
		this.isLocked = true;
	}

	/**
	 * Releases the lock on the cache and processes the next queued operation
	 */
	private unlock(): void {
		this.isLocked = false;
		const next = this.lockQueue.shift();
		if (next) {
			this.isLocked = true;
			next();
		}
	}

	/**
	 * Removes all stale entries from the cache
	 * Traverses the linked list from tail (LRU) to head (MRU)
	 */
	async purgeStale(): Promise<void> {
		await this.lock();
		try {
			// Start from the tail (least recently used) and move towards the head
			for (let i = this.tail; i !== 0; i = this.next[i]) {
				if (this.isStale(i)) {
					const node = this.nodes[i];
					if (!node) continue;
					await this.delete(node.key, true);
				}
				if (i === this.head) break;
			}
		} finally {
			this.unlock();
		}
	}

	/**
	 * Retrieves a value from the cache by its key
	 * Updates the item's position in the LRU list (moves to front)
	 *
	 * @param uid The key to look up
	 * @returns The cached value or undefined if not found or stale
	 */
	async get(uid: string): Promise<T | undefined> {
		if (typeof uid !== "string") {
			throw new RequestError("UID must be a string");
		}
		await this.lock();
		try {
			const index = this.cache.get(uid);
			if (index === undefined) return undefined;

			const node = this.nodes[index];
			if (!node) return undefined;

			// Check if the entry is stale and handle accordingly
			if (this.ttl && this.isStale(index)) {
				if (this.ttlAutoPurge) {
					await this.delete(uid);
				}
				return undefined;
			}

			// Move to front of LRU list (most recently used)
			this.moveToFront(index);
			node.timestamp = Date.now(); // Update timestamp on access
			return node.value;
		} finally {
			this.unlock();
		}
	}

	/**
	 * Stores a value in the cache with the given key
	 * If the key already exists, updates the value and moves to front
	 * If the cache is full, evicts least recently used items
	 *
	 * @param uid The key to store
	 * @param value The value to store
	 * @param size Optional size of the item for memory-aware caching
	 */
	async set(uid: string, value: T, size?: number): Promise<void> {
		if (typeof uid !== "string") {
			throw new RequestError("UID must be a string");
		}
		await this.lock();
		try {
			const calcSize = size ?? 1;
			if (!isPositiveInt(calcSize)) {
				throw new RequestError("Size must be a positive integer");
			}
			// If the item is larger than the maximum size, don't store it
			if (calcSize > this.maxSize) {
				return;
			}

			// Check if the key already exists in the cache
			let index = this.cache.get(uid);
			if (index !== undefined) {
				// Update existing entry
				const oldNode = this.nodes[index];
				if (!oldNode) return;
				const oldSize = oldNode.size ?? 0;
				oldNode.value = value;
				oldNode.size = calcSize;
				oldNode.timestamp = Date.now();
				this.moveToFront(index);
				this.totalSize = this.totalSize - oldSize + calcSize;

				// Ensure we're still within size limits after update
				while (this.totalSize > this.maxSize && this.currentSize > 0) {
					await this.evict();
				}
				return;
			}

			// Make room for the new entry if needed
			while (
				(this.currentSize >= this.capacity ||
					this.totalSize + calcSize > this.maxSize) &&
				this.currentSize > 0
			) {
				await this.evict();
			}

			// If we still can't fit the new entry, don't store it
			if (this.totalSize + calcSize > this.maxSize || this.free.length === 0) {
				return;
			}

			// Create and store the new entry
			index = this.free.pop()!;
			const node = new Node<T>(uid, value);
			node.size = calcSize;

			this.nodes[index] = node;
			this.cache.set(uid, index);
			this.addToFront(index);
			this.currentSize++;
			this.totalSize += calcSize;
		} finally {
			this.unlock();
		}
	}

	/**
	 * Removes an item from the cache by its key
	 *
	 * @param uid The key to remove
	 * @param skipLock Whether to skip acquiring the lock (used internally)
	 * @returns True if the item was found and removed, false otherwise
	 */
	async delete(uid: string, skipLock = false): Promise<boolean> {
		if (typeof uid !== "string") {
			throw new RequestError("UID must be a string");
		}
		if (!skipLock) {
			await this.lock();
		}
		try {
			const index = this.cache.get(uid);
			if (index === undefined) return false;

			const node = this.nodes[index];
			if (!node) return false;
			this.totalSize -= node.size ?? 0;

			// Update linked list pointers based on node position
			if (this.currentSize === 1) {
				// Last item in the cache
				this.head = 0;
				this.tail = 0;
			} else if (index === this.head) {
				// Head of the list
				this.head = this.next[index];
				this.prev[this.head] = 0;
			} else if (index === this.tail) {
				// Tail of the list
				this.tail = this.prev[index];
				this.next[this.tail] = 0;
			} else {
				// Middle of the list
				this.next[this.prev[index]] = this.next[index];
				this.prev[this.next[index]] = this.prev[index];
			}

			// Clean up and return the node to the free list
			this.cache.delete(uid);
			this.nodes[index] = undefined;
			this.free.push(index);
			this.currentSize--;
			return true;
		} finally {
			if (!skipLock) {
				this.unlock();
			}
		}
	}

	/**
	 * Returns the current number of items in the cache
	 */
	getSize(): number {
		return this.currentSize;
	}

	/**
	 * Removes all items from the cache
	 */
	async clear(): Promise<void> {
		await this.lock();
		try {
			this.cache.clear();
			this.nodes.fill(undefined);
			this.next.fill(0);
			this.prev.fill(0);
			this.head = 0;
			this.tail = 0;
			this.free = Array.from({ length: this.capacity }, (_, i) => i);
			this.currentSize = 0;
			this.totalSize = 0;
		} finally {
			this.unlock();
		}
	}

	/**
	 * Moves a node to the front of the linked list (most recently used position)
	 *
	 * @param index Index of the node to move
	 */
	private moveToFront(index: number): void {
		if (index === this.head) return; // Already at the front

		// Remove from current position
		if (index === this.tail) {
			// If it's the tail, update tail pointer
			this.tail = this.prev[index];
			this.next[this.tail] = 0;
		} else {
			// If it's in the middle, update surrounding nodes
			this.next[this.prev[index]] = this.next[index];
			this.prev[this.next[index]] = this.prev[index];
		}

		// Insert at the front
		this.next[index] = this.head;
		this.prev[this.head] = index;
		this.prev[index] = 0;
		this.head = index;
	}

	/**
	 * Adds a node to the front of the linked list
	 *
	 * @param index Index of the node to add
	 */
	private addToFront(index: number): void {
		if (this.currentSize === 0) {
			// First item in an empty list
			this.head = index;
			this.tail = index;
			this.next[index] = 0;
			this.prev[index] = 0;
		} else {
			// Add to the front of a non-empty list
			this.prev[this.head] = index;
			this.next[index] = this.head;
			this.prev[index] = 0;
			this.head = index;
		}
	}

	/**
	 * Removes the least recently used item from the cache
	 * This is called when the cache is full and a new item needs to be added
	 */
	private async evict(): Promise<void> {
		if (this.currentSize === 0) return;

		const index = this.tail; // The tail is the least recently used item
		const node = this.nodes[index];
		if (!node) return;

		// Update tail pointer
		this.tail = this.prev[index];
		if (this.currentSize === 1) {
			// Last item in the cache
			this.head = 0;
			this.tail = 0;
		} else {
			// Update the new tail's next pointer
			this.next[this.tail] = 0;
		}

		// Clean up and return the node to the free list
		this.cache.delete(node.key);
		this.nodes[index] = undefined;
		this.free.push(index);
		this.currentSize--;
		this.totalSize -= node.size ?? 0;
	}
}
