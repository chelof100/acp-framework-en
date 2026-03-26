package main

import (
	"context"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/chelof100/acp-framework/acp-go/pkg/risk"
)

// readCache implements risk.LedgerQuerier from values prefetched in a single
// Redis pipeline. A readCache is created per-request by
// RedisPipelinedQuerier.RunRequest and is not shared between requests.
type readCache struct {
	reqCount      int64
	denCount      int64
	patCount      int64
	cooldownUntil time.Time
}

func (c *readCache) CountRequests(_ string, _ time.Duration, _ time.Time) (int, error) {
	return int(c.reqCount), nil
}

func (c *readCache) CountDenials(_ string, _ time.Time) (int, error) {
	return int(c.denCount), nil
}

func (c *readCache) CountPattern(_ string, _ time.Time) (int, error) {
	return int(c.patCount), nil
}

func (c *readCache) CooldownActive(_ string, now time.Time) bool {
	return !c.cooldownUntil.IsZero() && now.Before(c.cooldownUntil)
}

func (c *readCache) CooldownUntil(_ string) time.Time {
	return c.cooldownUntil
}

// RedisPipelinedQuerier reduces per-request Redis round-trips from ~7–8 to 2
// by batching all reads into one pipeline before Evaluate and all writes into
// one pipeline after Evaluate.
//
// RTT budget per request:
//
//	Pipeline 1 (reads):  ZCount(req) + ZCount(denial) + ZCount(pattern) + GET(cooldown) → 1 RTT
//	Evaluate:            zero RTTs (LedgerQuerier served from readCache)
//	Pipeline 2 (writes): ZAdd(req) + ZAdd(pattern) + maybe ZAdd(denial)
//	                     + maybe SET(cooldown) → 1 RTT
//	Total: 2 RTTs  (vs ~7–8 for single-command baseline RedisQuerier)
//
// Key schema is identical to RedisQuerier; Flush() and Close() share the same
// implementation so the two backends can be compared against the same data.
type RedisPipelinedQuerier struct {
	client  *goredis.Client
	counter int64
}

// NewRedisPipelinedQuerier connects to Redis at addr and verifies connectivity.
func NewRedisPipelinedQuerier(addr string) (*RedisPipelinedQuerier, error) {
	c := goredis.NewClient(&goredis.Options{Addr: addr})
	if err := c.Ping(context.Background()).Err(); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("redis ping failed: %w", err)
	}
	return &RedisPipelinedQuerier{client: c}, nil
}

// Close closes the underlying Redis client.
func (q *RedisPipelinedQuerier) Close() error {
	return q.client.Close()
}

// Flush deletes all acp:* keys. Call between experiment runs.
func (q *RedisPipelinedQuerier) Flush() {
	ctx := context.Background()
	keys, err := q.client.Keys(ctx, "acp:*").Result()
	if err != nil || len(keys) == 0 {
		return
	}
	q.client.Del(ctx, keys...)
}

// RunRequest executes the full ACP-RISK-2.0 execution contract for one request
// using two Redis pipeline round-trips.
//
// Execution contract (ACP-RISK-2.0 §4) preserved exactly:
//  1. Reads prefetched in Pipeline 1 (state before this request's mutations)
//  2. Evaluate uses readCache (no additional RTTs)
//  3. AddRequest + AddPattern always in Pipeline 2
//  4. AddDenial only on real DENIED (Pipeline 2, conditional)
//  5. SetCooldown if denial threshold reached (Pipeline 2, conditional)
//     — threshold checked using prefetched count + 1, semantically equivalent
//     to calling ShouldEnterCooldown after flushing the denial write.
func (q *RedisPipelinedQuerier) RunRequest(req risk.EvalRequest, policy risk.PolicyConfig) *risk.EvalResult {
	now := time.Now()
	req.Now = now
	req.Policy = policy
	ctx := context.Background()

	patKey := risk.PatternKey(req.AgentID, req.Capability, req.Resource)

	reqKey     := "acp:req:" + req.AgentID
	denKey     := "acp:denial:" + req.AgentID
	patternKey := "acp:pattern:" + patKey
	cdKey      := "acp:cooldown:" + req.AgentID

	nowNs     := strconv.FormatInt(now.UnixNano(), 10)
	reqWinMin := strconv.FormatInt(now.Add(-60*time.Second).UnixNano(), 10)
	denWinMin := strconv.FormatInt(now.Add(-24*time.Hour).UnixNano(), 10)
	patWinMin := strconv.FormatInt(now.Add(-5*time.Minute).UnixNano(), 10)

	// ── Pipeline 1: 4 reads in 1 RTT ─────────────────────────────────────
	rPipe := q.client.Pipeline()
	rcCmd  := rPipe.ZCount(ctx, reqKey,     reqWinMin, nowNs)
	dcCmd  := rPipe.ZCount(ctx, denKey,     denWinMin, nowNs)
	pcCmd  := rPipe.ZCount(ctx, patternKey, patWinMin, nowNs)
	cdCmd  := rPipe.Get(ctx, cdKey)
	rPipe.Exec(ctx) // 1 RTT — ignore batch-level error; per-cmd errors handled below

	rc := &readCache{
		reqCount: rcCmd.Val(),
		denCount: dcCmd.Val(),
		patCount: pcCmd.Val(),
	}
	if val, err := cdCmd.Result(); err == nil {
		if ns, err := strconv.ParseInt(val, 10, 64); err == nil {
			rc.cooldownUntil = time.Unix(0, ns)
		}
	}

	// ── Evaluate (0 RTTs — served from readCache) ─────────────────────────
	result, err := risk.Evaluate(req, rc)
	if err != nil {
		return &risk.EvalResult{Decision: risk.DENIED, DeniedReason: "QUERIER_ERROR"}
	}

	// ── Pipeline 2: writes in 1 RTT ───────────────────────────────────────
	id  := strconv.FormatInt(atomic.AddInt64(&q.counter, 1), 10)
	tsf := float64(now.UnixNano())
	wPipe := q.client.Pipeline()

	wPipe.ZAdd(ctx, reqKey,     goredis.Z{Score: tsf, Member: id + "r"})
	wPipe.ZAdd(ctx, patternKey, goredis.Z{Score: tsf, Member: id + "p"})

	isRealDenied := result.Decision == risk.DENIED && result.DeniedReason != "COOLDOWN_ACTIVE"
	if isRealDenied {
		wPipe.ZAdd(ctx, denKey, goredis.Z{Score: tsf, Member: id + "d"})
	}

	// Cooldown gate: denial count + 1 (the pending write) vs threshold.
	// Equivalent to ShouldEnterCooldown called after flushing the denial.
	if isRealDenied && !rc.CooldownActive(req.AgentID, now) {
		if rc.denCount+1 >= int64(policy.CooldownTriggerDenials) {
			until := now.Add(time.Duration(policy.CooldownPeriodSeconds) * time.Second)
			wPipe.Set(ctx, cdKey,
				strconv.FormatInt(until.UnixNano(), 10),
				time.Until(until)+time.Minute,
			)
		}
	}

	wPipe.Exec(ctx) // 1 RTT

	return result
}
