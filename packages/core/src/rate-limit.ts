/**
 * In-memory sliding window rate limiter.
 *
 * Tracks requests per key (API key ID or session subject) in a 1-minute
 * sliding window.  Supports a configurable per-minute limit and burst
 * allowance (extra requests tolerated in a short spike).
 */

export interface RateLimitResult {
  /** Whether the request is allowed */
  allowed: boolean;
  /** Number of requests used in the current window */
  used: number;
  /** Maximum requests allowed in the window (rpm + burst) */
  limit: number;
  /** Seconds until the oldest tracked request falls outside the window */
  retryAfterSecs: number;
}

export interface RateLimiterOptions {
  /** Default requests per minute */
  rpm: number;
  /** Burst allowance — extra requests above rpm allowed in a window */
  burst: number;
}

const DEFAULT_OPTIONS: RateLimiterOptions = {
  rpm: 60,
  burst: 10,
};

const WINDOW_MS = 60_000; // 1 minute sliding window

export class RateLimiter {
  /** key → sorted array of request timestamps (ms) */
  private windows: Map<string, number[]> = new Map();
  private defaults: RateLimiterOptions;
  /** key → per-key rpm override */
  private overrides: Map<string, number> = new Map();

  constructor(opts?: Partial<RateLimiterOptions>) {
    this.defaults = { ...DEFAULT_OPTIONS, ...opts };
  }

  /**
   * Set a per-key RPM override. Pass `null` to clear the override
   * and revert to the global default.
   */
  setKeyLimit(key: string, rpm: number | null): void {
    if (rpm === null) {
      this.overrides.delete(key);
    } else {
      this.overrides.set(key, rpm);
    }
  }

  /**
   * Check whether a request from `key` should be allowed and, if so,
   * record it in the sliding window.
   */
  check(key: string): RateLimitResult {
    const now = Date.now();
    const cutoff = now - WINDOW_MS;

    // Get or create window for this key
    let timestamps = this.windows.get(key);
    if (!timestamps) {
      timestamps = [];
      this.windows.set(key, timestamps);
    }

    // Prune entries older than the window
    while (timestamps.length > 0 && timestamps[0] <= cutoff) {
      timestamps.shift();
    }

    // Determine effective limit
    const rpm = this.overrides.get(key) ?? this.defaults.rpm;
    const limit = rpm + this.defaults.burst;
    const used = timestamps.length;

    if (used >= limit) {
      // Compute retry-after: seconds until the oldest entry expires out of the window
      const oldestTs = timestamps[0];
      const retryAfterMs = oldestTs + WINDOW_MS - now;
      const retryAfterSecs = Math.max(1, Math.ceil(retryAfterMs / 1000));
      return { allowed: false, used, limit, retryAfterSecs };
    }

    // Record the request
    timestamps.push(now);
    return { allowed: true, used: used + 1, limit, retryAfterSecs: 0 };
  }

  /**
   * Reset the window for a given key (useful for testing or key rotation).
   */
  reset(key: string): void {
    this.windows.delete(key);
  }

  /**
   * Clear all tracked state.
   */
  clear(): void {
    this.windows.clear();
    this.overrides.clear();
  }
}
