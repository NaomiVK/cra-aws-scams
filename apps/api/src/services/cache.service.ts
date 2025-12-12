import { Injectable, Logger } from '@nestjs/common';
import NodeCache from 'node-cache';
import { environment } from '../environments/environment';

@Injectable()
export class CacheService {
  private readonly logger = new Logger(CacheService.name);
  private readonly cache: NodeCache;

  constructor() {
    this.cache = new NodeCache({
      stdTTL: environment.cache.analyticsTtl,
      checkperiod: 600, // Check for expired keys every 10 minutes
      useClones: false, // For better performance with large objects
    });

    this.logger.log('CacheService initialized');
  }

  /**
   * Get a value from cache
   */
  get<T>(key: string): T | undefined {
    try {
      return this.cache.get<T>(key);
    } catch (error) {
      this.logger.error(`Cache get error for key ${key}:`, error);
      return undefined;
    }
  }

  /**
   * Set a value in cache with optional TTL
   */
  set<T>(key: string, value: T, ttlSeconds?: number): boolean {
    try {
      if (ttlSeconds) {
        return this.cache.set(key, value, ttlSeconds);
      }
      return this.cache.set(key, value);
    } catch (error) {
      this.logger.error(`Cache set error for key ${key}:`, error);
      return false;
    }
  }

  /**
   * Delete a key from cache
   */
  del(key: string): number {
    return this.cache.del(key);
  }

  /**
   * Delete multiple keys matching a pattern
   */
  delByPattern(pattern: string): number {
    const keys = this.cache.keys().filter((key) => key.includes(pattern));
    return this.cache.del(keys);
  }

  /**
   * Check if key exists
   */
  has(key: string): boolean {
    return this.cache.has(key);
  }

  /**
   * Get all keys
   */
  keys(): string[] {
    return this.cache.keys();
  }

  /**
   * Flush all cache
   */
  flush(): void {
    this.cache.flushAll();
    this.logger.log('Cache flushed');
  }

  /**
   * Get cache statistics
   */
  getStats(): NodeCache.Stats {
    return this.cache.getStats();
  }

  /**
   * Get or set pattern - retrieve from cache or fetch and cache
   */
  async getOrSet<T>(
    key: string,
    fetchFn: () => Promise<T>,
    ttlSeconds?: number
  ): Promise<T> {
    const cached = this.get<T>(key);
    if (cached !== undefined) {
      this.logger.debug(`Cache hit for key: ${key}`);
      return cached;
    }

    this.logger.debug(`Cache miss for key: ${key}, fetching...`);
    const value = await fetchFn();
    // Don't cache null/undefined values - they likely represent failures
    if (value !== null && value !== undefined) {
      this.set(key, value, ttlSeconds);
    }
    return value;
  }
}
