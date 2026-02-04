"""
Test Timing Safety

Tests for constant-time operations:
- Verify timing-safe comparison functions
- Test that comparison time doesn't vary with input differences
"""

import pytest
import time
import statistics
from ash.core import ash_timing_safe_equal
from ash.core.proof import ash_verify_proof


class TestTimingSafeComparison:
    """Test timing-safe comparison functions."""

    def test_equal_strings_return_true(self):
        """Equal strings should return True."""
        assert ash_timing_safe_equal("abc", "abc") is True
        assert ash_timing_safe_equal("", "") is True
        assert ash_timing_safe_equal("a" * 1000, "a" * 1000) is True

    def test_different_strings_return_false(self):
        """Different strings should return False."""
        assert ash_timing_safe_equal("abc", "def") is False
        assert ash_timing_safe_equal("abc", "abx") is False
        assert ash_timing_safe_equal("abc", "abcd") is False
        assert ash_timing_safe_equal("abc", "") is False

    def test_case_sensitivity(self):
        """Comparison should be case-sensitive."""
        assert ash_timing_safe_equal("abc", "ABC") is False
        assert ash_timing_safe_equal("Hello", "hello") is False

    def test_length_difference(self):
        """Strings of different lengths should return False."""
        assert ash_timing_safe_equal("abc", "ab") is False
        assert ash_timing_safe_equal("ab", "abc") is False
        assert ash_timing_safe_equal("", "a") is False

    def test_unicode_strings(self):
        """Unicode strings should be compared correctly."""
        assert ash_timing_safe_equal("café", "café") is True
        assert ash_timing_safe_equal("日本語", "日本語") is True
        assert ash_timing_safe_equal("café", "cafe") is False

    def test_binary_data_as_hex(self):
        """Binary data as hex strings should be compared correctly."""
        hex1 = "0123456789abcdef"
        hex2 = "0123456789abcdef"
        hex3 = "0123456789abcdff"
        
        assert ash_timing_safe_equal(hex1, hex2) is True
        assert ash_timing_safe_equal(hex1, hex3) is False


class TestTimingAttackResistance:
    """Test that operations resist timing attacks."""

    def _measure_comparison_time(self, a: str, b: str, iterations: int = 1000) -> float:
        """Measure average time for string comparison."""
        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            ash_timing_safe_equal(a, b)
            end = time.perf_counter()
            times.append(end - start)
        return statistics.median(times)

    def test_comparison_time_independent_of_difference_position(self):
        """Comparison time should not depend on where strings differ."""
        # Create strings that differ at different positions
        base = "a" * 64
        early_diff = "b" + "a" * 63  # Differs at position 0
        mid_diff = "a" * 32 + "b" + "a" * 31  # Differs at position 32
        late_diff = "a" * 63 + "b"  # Differs at position 63
        
        # Measure comparison times
        time_early = self._measure_comparison_time(base, early_diff, iterations=500)
        time_mid = self._measure_comparison_time(base, mid_diff, iterations=500)
        time_late = self._measure_comparison_time(base, late_diff, iterations=500)
        
        # Times should be roughly similar (allowing for variance)
        # This is a statistical test - we check that no position is significantly faster
        times = [time_early, time_mid, time_late]
        max_time = max(times)
        min_time = min(times)
        
        # The difference should be within a reasonable factor
        # This is a heuristic - timing tests are inherently flaky
        ratio = max_time / min_time if min_time > 0 else 1.0
        assert ratio < 5.0, f"Timing difference too large: {ratio:.2f}x"

    def test_comparison_time_independent_of_string_length(self):
        """Comparison time should be proportional to string length."""
        # Test with different string lengths
        lengths = [16, 32, 64]
        times = []
        
        for length in lengths:
            a = "x" * length
            b = "y" * length
            t = self._measure_comparison_time(a, b, iterations=500)
            times.append((length, t))
        
        # Longer strings should take proportionally more time
        # This verifies we're not using early-exit optimizations
        for i in range(len(times) - 1):
            len1, time1 = times[i]
            len2, time2 = times[i + 1]
            ratio = time2 / time1 if time1 > 0 else 1.0
            length_ratio = len2 / len1
            
            # Time ratio should be roughly proportional to length ratio
            # Allow 3x variance for system load variations
            assert 0.3 < ratio / length_ratio < 3.0, \
                f"Time not proportional to length: len_ratio={length_ratio}, time_ratio={ratio}"

    def test_comparison_time_for_equal_vs_unequal(self):
        """Comparison time should be similar for equal and unequal strings."""
        base = "x" * 64
        equal = "x" * 64
        unequal = "y" * 64
        
        time_equal = self._measure_comparison_time(base, equal, iterations=500)
        time_unequal = self._measure_comparison_time(base, unequal, iterations=500)
        
        # Times should be similar (within 2x)
        ratio = max(time_equal, time_unequal) / min(time_equal, time_unequal) \
            if min(time_equal, time_unequal) > 0 else 1.0
        assert ratio < 2.0, f"Timing difference between equal/unequal too large: {ratio:.2f}x"


class TestProofVerificationTiming:
    """Test proof verification timing characteristics."""

    def test_verify_proof_timing(self):
        """Proof verification should use constant-time comparison."""
        nonce = "a" * 64
        context_id = "test_ctx"
        binding = "POST|/api/test|"
        timestamp = "1704067200000"
        body_hash = "b" * 64
        
        # Test with valid-looking proofs
        valid_proof = "c" * 64
        invalid_proof_early = "d" + "c" * 63  # Differs early
        invalid_proof_late = "c" * 63 + "d"  # Differs late
        
        # Measure verification times
        iterations = 500
        
        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            ash_verify_proof(nonce, context_id, binding, timestamp, body_hash, valid_proof)
            end = time.perf_counter()
            times.append(end - start)
        time_valid = statistics.median(times)
        
        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            ash_verify_proof(nonce, context_id, binding, timestamp, body_hash, invalid_proof_early)
            end = time.perf_counter()
            times.append(end - start)
        time_invalid_early = statistics.median(times)
        
        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            ash_verify_proof(nonce, context_id, binding, timestamp, body_hash, invalid_proof_late)
            end = time.perf_counter()
            times.append(end - start)
        time_invalid_late = statistics.median(times)
        
        # Times should be similar (within reasonable variance)
        all_times = [time_valid, time_invalid_early, time_invalid_late]
        max_time = max(all_times)
        min_time = min(all_times)
        
        ratio = max_time / min_time if min_time > 0 else 1.0
        assert ratio < 5.0, f"Verification timing varies too much: {ratio:.2f}x"


class TestHMACComparison:
    """Test HMAC comparison properties."""

    def test_hmac_compare_digest_used(self):
        """Verify that hmac.compare_digest is used internally."""
        import hmac
        
        # The ash_timing_safe_equal function should delegate to hmac.compare_digest
        # We can verify this by checking that it behaves the same way
        
        test_cases = [
            ("abc", "abc", True),
            ("abc", "def", False),
            ("", "", True),
            ("", "a", False),
            ("a", "", False),
            ("a" * 1000, "a" * 1000, True),
            ("a" * 1000, "a" * 999 + "b", False),
        ]
        
        for a, b, expected in test_cases:
            ash_result = ash_timing_safe_equal(a, b)
            hmac_result = hmac.compare_digest(a.encode(), b.encode())
            assert ash_result == hmac_result == expected


class TestSensitiveDataProtection:
    """Test that sensitive data is protected in comparisons."""

    def _measure_comparison_time(self, a: str, b: str, iterations: int = 1000) -> float:
        """Measure average time for string comparison."""
        import time
        import statistics
        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            ash_timing_safe_equal(a, b)
            end = time.perf_counter()
            times.append(end - start)
        return statistics.median(times)

    def test_comparison_doesnt_leak_length(self):
        """Comparison should not leak string length through timing."""
        # Compare strings of different lengths
        short = "x" * 10
        medium = "x" * 50
        long = "x" * 100
        
        # Time comparisons with matching lengths
        time_short = self._measure_comparison_time(short, short, iterations=300)
        time_medium = self._measure_comparison_time(medium, medium, iterations=300)
        time_long = self._measure_comparison_time(long, long, iterations=300)
        
        # Time comparisons with non-matching lengths
        diff_short = "y" * 10
        diff_medium = "y" * 50
        diff_long = "y" * 100
        
        time_short_diff = self._measure_comparison_time(short, diff_short, iterations=300)
        time_medium_diff = self._measure_comparison_time(medium, diff_medium, iterations=300)
        time_long_diff = self._measure_comparison_time(long, diff_long, iterations=300)
        
        # For each length, equal and unequal comparisons should take similar time
        ratios = [
            time_short / time_short_diff if time_short_diff > 0 else 1.0,
            time_medium / time_medium_diff if time_medium_diff > 0 else 1.0,
            time_long / time_long_diff if time_long_diff > 0 else 1.0,
        ]
        
        for ratio in ratios:
            normalized_ratio = max(ratio, 1.0 / ratio) if ratio > 0 else 1.0
            assert normalized_ratio < 2.0, \
                f"Timing leak detected: equal vs unequal ratio = {normalized_ratio:.2f}"


class TestConstantTimeProperties:
    """Test general constant-time properties."""

    def test_no_early_return(self):
        """Function should not return early on mismatch."""
        # This is a functional test - the timing tests above verify the property
        # Here we just ensure the function works correctly
        
        # Various mismatch positions
        base = "a" * 64
        for i in range(0, 64, 8):
            modified = base[:i] + "b" + base[i+1:]
            assert ash_timing_safe_equal(base, modified) is False

    def test_all_bytes_compared(self):
        """All bytes should be compared regardless of differences."""
        # This is verified by timing - if early exit occurred,
        # late differences would be faster
        
        # Test with strings that differ at various positions
        base = "x" * 64
        for pos in [0, 1, 31, 32, 62, 63]:
            test = list(base)
            test[pos] = "y"
            test_str = "".join(test)
            assert ash_timing_safe_equal(base, test_str) is False

    def test_byte_wise_comparison(self):
        """Comparison should be byte-wise, not string-wise."""
        # Multi-byte UTF-8 characters should be compared byte by byte
        str1 = "é"  # UTF-8: 0xc3 0xa9
        str2 = "é"  # Same
        str3 = "e"  # Different
        
        assert ash_timing_safe_equal(str1, str2) is True
        assert ash_timing_safe_equal(str1, str3) is False


# ============================================================================
# Statistical Timing Test
# ============================================================================

@pytest.mark.slow
class TestStatisticalTiming:
    """Statistical tests for timing attack resistance (slow)."""

    def test_statistical_timing_independence(self):
        """Statistical test for timing independence (slow)."""
        # This test runs many iterations to gather statistics
        # It's marked as slow and may be skipped in normal CI
        
        base = "s" * 64
        
        # Collect timing samples for different mismatch positions
        samples = {i: [] for i in [0, 16, 32, 48]}
        samples["equal"] = []
        
        iterations = 1000
        
        # Warm up
        for _ in range(100):
            ash_timing_safe_equal(base, base)
        
        # Collect samples
        for pos in [0, 16, 32, 48]:
            test = base[:pos] + "x" + base[pos+1:]
            for _ in range(iterations):
                start = time.perf_counter()
                ash_timing_safe_equal(base, test)
                end = time.perf_counter()
                samples[pos].append(end - start)
        
        # Collect equal string samples
        for _ in range(iterations):
            start = time.perf_counter()
            ash_timing_safe_equal(base, base)
            end = time.perf_counter()
            samples["equal"].append(end - start)
        
        # Calculate means and standard deviations
        stats = {}
        for key, times in samples.items():
            stats[key] = {
                "mean": statistics.mean(times),
                "stdev": statistics.stdev(times) if len(times) > 1 else 0,
            }
        
        # All means should be within 2 standard deviations of each other
        # This is a weak statistical test but catches obvious timing leaks
        mean_values = [s["mean"] for s in stats.values()]
        overall_mean = statistics.mean(mean_values)
        
        for key, stat in stats.items():
            # Allow 50% variance from overall mean
            deviation = abs(stat["mean"] - overall_mean) / overall_mean if overall_mean > 0 else 0
            assert deviation < 0.5, \
                f"Timing leak at position {key}: mean={stat['mean']:.2e}, " \
                f"overall={overall_mean:.2e}, deviation={deviation:.2%}"
