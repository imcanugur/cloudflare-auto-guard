/**
 * Shared utility functions
 */

/**
 * 32-bit FNV-1a hash algorithm for fast, uniform key distribution
 */
export function fnv1a(str: string): number {
  let hash = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
  }
  return hash >>> 0;
}

/**
 * Maps an IP to a designated shard index
 */
export function getShardIndex(key: string, shardCount: number): number {
  if (shardCount <= 0) return 0;
  return fnv1a(key) % shardCount;
}

/**
 * Returns current timestamp in epoch milliseconds
 */
export function nowMs(): number {
  return Date.now();
}

/**
 * Returns bucket identifier for a given timestamp and window interval
 */
export function getBucketId(timestampMs: number, bucketSizeSeconds: number): number {
  const bucketSizeMs = bucketSizeSeconds * 1000;
  return Math.floor(timestampMs / bucketSizeMs) * bucketSizeMs;
}
