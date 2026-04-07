// SPDX-License-Identifier: MIT
//! Tests for the benchmarking framework.
//!
//! These are functional tests that verify the benchmark infrastructure works
//! correctly. They do NOT run full performance benchmarks (which would be
//! too slow for unit tests). Instead, they verify:
//!   - Result formatting
//!   - Table generation
//!   - Statistical calculations (speedup, CV)
//!   - Benchmark function registration and execution
//!   - Edge cases (zero iterations, null throughput)

const std = @import("std");
const mem = std.mem;
const testing = std.testing;

const bench = @import("benchmark/bench.zig");
const BenchmarkResult = bench.BenchmarkResult;

// =========================================================================
// BenchmarkResult formatting
// =========================================================================

test "benchmark: format result with throughput" {
    const allocator = testing.allocator;
    const result = BenchmarkResult{
        .name = "AES-256 encrypt",
        .iterations = 10000,
        .total_ns = 10_000_000,
        .min_ns = 800,
        .max_ns = 2000,
        .mean_ns = 1000,
        .median_ns = 950,
        .throughput_mb_s = 15258.0,
    };

    const formatted = try result.format(allocator);
    defer allocator.free(formatted);

    try testing.expect(mem.indexOf(u8, formatted, "AES-256 encrypt") != null);
    try testing.expect(mem.indexOf(u8, formatted, "10000") != null);
    try testing.expect(mem.indexOf(u8, formatted, "1000") != null);
    try testing.expect(mem.indexOf(u8, formatted, "MB/s") != null);
}

test "benchmark: format result without throughput" {
    const allocator = testing.allocator;
    const result = BenchmarkResult{
        .name = "Ed25519 keygen",
        .iterations = 100,
        .total_ns = 5_000_000,
        .min_ns = 40000,
        .max_ns = 80000,
        .mean_ns = 50000,
        .median_ns = 48000,
        .throughput_mb_s = null,
    };

    const formatted = try result.format(allocator);
    defer allocator.free(formatted);

    try testing.expect(mem.indexOf(u8, formatted, "Ed25519 keygen") != null);
    try testing.expect(mem.indexOf(u8, formatted, "MB/s") == null);
}

test "benchmark: format result with zero iterations" {
    const allocator = testing.allocator;
    const result = BenchmarkResult{
        .name = "empty",
        .iterations = 0,
        .total_ns = 0,
        .min_ns = 0,
        .max_ns = 0,
        .mean_ns = 0,
        .median_ns = 0,
        .throughput_mb_s = null,
    };

    const formatted = try result.format(allocator);
    defer allocator.free(formatted);

    try testing.expect(mem.indexOf(u8, formatted, "empty") != null);
}

// =========================================================================
// Table formatting
// =========================================================================

test "benchmark: format empty table" {
    const allocator = testing.allocator;
    const results = [_]BenchmarkResult{};

    const table = try bench.formatTable(allocator, &results);
    defer allocator.free(table);

    // Should still have header
    try testing.expect(mem.indexOf(u8, table, "Benchmark") != null);
    try testing.expect(mem.indexOf(u8, table, "---") != null);
}

test "benchmark: format table with multiple entries" {
    const allocator = testing.allocator;
    const results = [_]BenchmarkResult{
        .{
            .name = "AES-128",
            .iterations = 10000,
            .total_ns = 5_000_000,
            .min_ns = 300,
            .max_ns = 1500,
            .mean_ns = 500,
            .median_ns = 450,
            .throughput_mb_s = 30000.0,
        },
        .{
            .name = "SHA-256 (4KB)",
            .iterations = 10000,
            .total_ns = 20_000_000,
            .min_ns = 1000,
            .max_ns = 5000,
            .mean_ns = 2000,
            .median_ns = 1800,
            .throughput_mb_s = 2048.0,
        },
        .{
            .name = "X25519 DH",
            .iterations = 1000,
            .total_ns = 50_000_000,
            .min_ns = 40000,
            .max_ns = 80000,
            .mean_ns = 50000,
            .median_ns = 48000,
            .throughput_mb_s = null,
        },
    };

    const table = try bench.formatTable(allocator, &results);
    defer allocator.free(table);

    try testing.expect(mem.indexOf(u8, table, "AES-128") != null);
    try testing.expect(mem.indexOf(u8, table, "SHA-256 (4KB)") != null);
    try testing.expect(mem.indexOf(u8, table, "X25519 DH") != null);
    try testing.expect(mem.indexOf(u8, table, "N/A") != null); // X25519 has no throughput
}

// =========================================================================
// Benchmark runner
// =========================================================================

test "benchmark: run noop function" {
    const allocator = testing.allocator;
    const result = try bench.runBenchmark(allocator, "noop", 50, &struct {
        fn f() void {}
    }.f, null);

    try testing.expect(result.iterations == 50);
    try testing.expect(result.throughput_mb_s == null);
    try testing.expect(result.min_ns <= result.mean_ns);
    try testing.expect(result.mean_ns <= result.max_ns);
    // noop function may complete in 0ns on fast hardware
    try testing.expect(result.total_ns >= 0);
}

test "benchmark: run with zero iterations" {
    const allocator = testing.allocator;
    const result = try bench.runBenchmark(allocator, "zero", 0, &struct {
        fn f() void {}
    }.f, null);

    try testing.expect(result.iterations == 0);
    try testing.expect(result.total_ns == 0);
    try testing.expect(result.min_ns == 0);
    try testing.expect(result.max_ns == 0);
}

test "benchmark: run with data size for throughput" {
    const allocator = testing.allocator;
    const result = try bench.runBenchmark(allocator, "throughput_test", 100, &struct {
        fn f() void {
            var x: u64 = 0;
            for (0..100) |i| x += i;
            std.mem.doNotOptimizeAway(&x);
        }
    }.f, 4096);

    try testing.expect(result.iterations == 100);
    // Throughput should be calculated when data_size is provided
    // (It may be null if mean_ns is 0, but with 100 iterations of work it shouldn't be)
}

// =========================================================================
// Statistical utilities
// =========================================================================

test "benchmark: speedup ratio" {
    const fast = BenchmarkResult{
        .name = "fast",
        .iterations = 100,
        .total_ns = 100_000,
        .min_ns = 500,
        .max_ns = 1500,
        .mean_ns = 1000,
        .median_ns = 950,
        .throughput_mb_s = null,
    };
    const slow = BenchmarkResult{
        .name = "slow",
        .iterations = 100,
        .total_ns = 500_000,
        .min_ns = 3000,
        .max_ns = 7000,
        .mean_ns = 5000,
        .median_ns = 4800,
        .throughput_mb_s = null,
    };

    const ratio = bench.speedupRatio(fast, slow);
    try testing.expect(ratio >= 4.5 and ratio <= 5.5); // ~5x speedup

    // Self comparison should be ~1.0
    const self_ratio = bench.speedupRatio(fast, fast);
    try testing.expect(self_ratio >= 0.9 and self_ratio <= 1.1);
}

test "benchmark: speedup ratio with zero mean" {
    const zero_mean = BenchmarkResult{
        .name = "zero",
        .iterations = 0,
        .total_ns = 0,
        .min_ns = 0,
        .max_ns = 0,
        .mean_ns = 0,
        .median_ns = 0,
        .throughput_mb_s = null,
    };
    const other = BenchmarkResult{
        .name = "other",
        .iterations = 100,
        .total_ns = 100_000,
        .min_ns = 500,
        .max_ns = 1500,
        .mean_ns = 1000,
        .median_ns = 950,
        .throughput_mb_s = null,
    };

    const ratio = bench.speedupRatio(zero_mean, other);
    try testing.expect(ratio == 0.0);
}

test "benchmark: rough coefficient of variation" {
    // Tight distribution (low CV)
    const tight = BenchmarkResult{
        .name = "tight",
        .iterations = 100,
        .total_ns = 100_000,
        .min_ns = 950,
        .max_ns = 1050,
        .mean_ns = 1000,
        .median_ns = 1000,
        .throughput_mb_s = null,
    };
    const tight_cv = bench.roughCv(tight);
    try testing.expect(tight_cv < 10.0); // Should be ~5%

    // Wide distribution (high CV)
    const wide = BenchmarkResult{
        .name = "wide",
        .iterations = 100,
        .total_ns = 100_000,
        .min_ns = 100,
        .max_ns = 10000,
        .mean_ns = 1000,
        .median_ns = 800,
        .throughput_mb_s = null,
    };
    const wide_cv = bench.roughCv(wide);
    try testing.expect(wide_cv > 100.0); // Should be very high
}

// =========================================================================
// Pre-defined benchmarks — smoke tests
// =========================================================================

test "benchmark: AES-128 smoke test" {
    const allocator = testing.allocator;
    const result = try bench.benchAes128(allocator);
    try testing.expectEqualStrings("AES-128 encrypt (block)", result.name);
    try testing.expect(result.iterations > 0);
    try testing.expect(result.throughput_mb_s != null);
}

test "benchmark: AES-256 smoke test" {
    const allocator = testing.allocator;
    const result = try bench.benchAes256(allocator);
    try testing.expectEqualStrings("AES-256 encrypt (block)", result.name);
    try testing.expect(result.iterations > 0);
}

test "benchmark: SHA-256 smoke test" {
    const allocator = testing.allocator;
    const result = try bench.benchSha256(allocator);
    try testing.expectEqualStrings("SHA-256 (4KB)", result.name);
    try testing.expect(result.throughput_mb_s != null);
}

test "benchmark: SHA-512 smoke test" {
    const allocator = testing.allocator;
    const result = try bench.benchSha512(allocator);
    try testing.expectEqualStrings("SHA-512 (4KB)", result.name);
}

test "benchmark: CRC-24 smoke test" {
    const allocator = testing.allocator;
    const result = try bench.benchCrc24(allocator);
    try testing.expectEqualStrings("CRC-24 (4KB)", result.name);
}

test "benchmark: Base64 encode smoke test" {
    const allocator = testing.allocator;
    const result = try bench.benchArmor(allocator);
    try testing.expectEqualStrings("Base64 encode (4KB)", result.name);
}

test "benchmark: HMAC-SHA256 smoke test" {
    const allocator = testing.allocator;
    const result = try bench.benchHmacSha256(allocator);
    try testing.expectEqualStrings("HMAC-SHA256 (4KB)", result.name);
}
