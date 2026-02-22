import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { RateLimiter } from "@quint-security/core";

describe("RateLimiter", () => {
  let limiter: RateLimiter;

  beforeEach(() => {
    limiter = new RateLimiter({ rpm: 5, burst: 2 });
  });

  it("allows requests under the limit", () => {
    // Limit = rpm (5) + burst (2) = 7
    const r1 = limiter.check("key-1");
    assert.equal(r1.allowed, true, "First request should be allowed");
    assert.equal(r1.used, 1);
    assert.equal(r1.limit, 7);
    assert.equal(r1.retryAfterSecs, 0);

    const r2 = limiter.check("key-1");
    assert.equal(r2.allowed, true, "Second request should be allowed");
    assert.equal(r2.used, 2);
  });

  it("allows requests up to the limit", () => {
    // Fill up to limit (5 rpm + 2 burst = 7)
    for (let i = 0; i < 7; i++) {
      const r = limiter.check("key-1");
      assert.equal(r.allowed, true, `Request ${i + 1} should be allowed`);
      assert.equal(r.used, i + 1);
    }
  });

  it("rejects requests over the limit", () => {
    // Fill to limit
    for (let i = 0; i < 7; i++) {
      limiter.check("key-1");
    }

    // 8th request should be rejected
    const r = limiter.check("key-1");
    assert.equal(r.allowed, false, "8th request should be rejected");
    assert.equal(r.used, 7);
    assert.equal(r.limit, 7);
    assert.ok(r.retryAfterSecs >= 1, `retryAfterSecs should be >= 1, got ${r.retryAfterSecs}`);
  });

  it("tracks keys independently", () => {
    // Fill up key-1
    for (let i = 0; i < 7; i++) {
      limiter.check("key-1");
    }
    const rKey1 = limiter.check("key-1");
    assert.equal(rKey1.allowed, false, "key-1 should be rate limited");

    // key-2 should still be allowed
    const rKey2 = limiter.check("key-2");
    assert.equal(rKey2.allowed, true, "key-2 should be allowed independently");
  });

  it("resets the window after reset()", () => {
    for (let i = 0; i < 7; i++) {
      limiter.check("key-1");
    }

    const rBefore = limiter.check("key-1");
    assert.equal(rBefore.allowed, false, "Should be rate limited");

    // Reset clears the window
    limiter.reset("key-1");

    const rAfter = limiter.check("key-1");
    assert.equal(rAfter.allowed, true, "Should be allowed after reset");
    assert.equal(rAfter.used, 1);
  });

  it("supports per-key rate limit overrides", () => {
    // Set a lower limit for key-1 (rpm=2, so limit = 2 + 2 burst = 4)
    limiter.setKeyLimit("key-1", 2);

    for (let i = 0; i < 4; i++) {
      const r = limiter.check("key-1");
      assert.equal(r.allowed, true, `Request ${i + 1} for key-1 should be allowed`);
    }

    const rOver = limiter.check("key-1");
    assert.equal(rOver.allowed, false, "key-1 should be rate limited at custom limit");
    assert.equal(rOver.limit, 4); // 2 rpm + 2 burst

    // key-2 still uses default limit (5 + 2 = 7)
    for (let i = 0; i < 7; i++) {
      const r = limiter.check("key-2");
      assert.equal(r.allowed, true, `Request ${i + 1} for key-2 should be allowed`);
    }
  });

  it("clears per-key override with null", () => {
    limiter.setKeyLimit("key-1", 2);

    // Verify the override is in effect
    for (let i = 0; i < 4; i++) {
      limiter.check("key-1");
    }
    assert.equal(limiter.check("key-1").allowed, false, "Should be limited at custom rate");

    // Clear override and reset window
    limiter.setKeyLimit("key-1", null);
    limiter.reset("key-1");

    // Now should use default limit (7)
    for (let i = 0; i < 7; i++) {
      const r = limiter.check("key-1");
      assert.equal(r.allowed, true, `Request ${i + 1} should be allowed with default limit`);
    }
    assert.equal(limiter.check("key-1").allowed, false, "Should be limited at default rate");
  });

  it("provides correct retryAfterSecs", () => {
    // Fill to limit
    for (let i = 0; i < 7; i++) {
      limiter.check("key-1");
    }

    const r = limiter.check("key-1");
    assert.equal(r.allowed, false);
    // retryAfterSecs should be roughly 60 seconds (the window is 60s)
    assert.ok(r.retryAfterSecs > 0, "retryAfterSecs should be positive");
    assert.ok(r.retryAfterSecs <= 60, `retryAfterSecs should be <= 60, got ${r.retryAfterSecs}`);
  });

  it("clear() resets all state", () => {
    for (let i = 0; i < 7; i++) {
      limiter.check("key-1");
      limiter.check("key-2");
    }

    assert.equal(limiter.check("key-1").allowed, false);
    assert.equal(limiter.check("key-2").allowed, false);

    limiter.clear();

    assert.equal(limiter.check("key-1").allowed, true, "key-1 should be allowed after clear");
    assert.equal(limiter.check("key-2").allowed, true, "key-2 should be allowed after clear");
  });

  it("uses default options when none provided", () => {
    const defaultLimiter = new RateLimiter();
    // Default: 60 rpm + 10 burst = 70
    const r = defaultLimiter.check("key-1");
    assert.equal(r.allowed, true);
    assert.equal(r.limit, 70);
  });
});
