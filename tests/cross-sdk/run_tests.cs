#!/usr/bin/env dotnet-script
/**
 * Cross-SDK Test Vector Runner for .NET
 *
 * Runs the standard ASH test vectors against the .NET SDK to verify
 * interoperability with other language implementations.
 *
 * Usage:
 *   dotnet run --project run_tests.csproj
 *   dotnet run --project run_tests.csproj -- --verbose
 *   dotnet run --project run_tests.csproj -- --category canonicalization
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Ash.Core;

namespace Ash.CrossSdkTests
{
    public class TestVectors
    {
        public CanonicalizationSection? Canonicalization { get; set; }
        public UrlencodedSection? UrlencodedCanonicalization { get; set; }
        public BindingSection? BindingNormalization { get; set; }
        public TimingSafeSection? TimingSafeEqual { get; set; }
    }

    public class CanonicalizationSection
    {
        public List<CanonicalizationVector>? Vectors { get; set; }
    }

    public class CanonicalizationVector
    {
        public string Id { get; set; } = "";
        public string Description { get; set; } = "";
        public string Input { get; set; } = "";
        public string Expected { get; set; } = "";
    }

    public class UrlencodedSection
    {
        public List<UrlencodedVector>? Vectors { get; set; }
    }

    public class UrlencodedVector
    {
        public string Id { get; set; } = "";
        public string Description { get; set; } = "";
        public string Input { get; set; } = "";
        public string Expected { get; set; } = "";
    }

    public class BindingSection
    {
        public List<BindingVector>? Vectors { get; set; }
    }

    public class BindingVector
    {
        public string Id { get; set; } = "";
        public string Description { get; set; } = "";
        public string Method { get; set; } = "";
        public string Path { get; set; } = "";
        public string Query { get; set; } = "";
        public string Expected { get; set; } = "";
    }

    public class TimingSafeSection
    {
        public List<TimingSafeVector>? Vectors { get; set; }
    }

    public class TimingSafeVector
    {
        public string Id { get; set; } = "";
        public string A { get; set; } = "";
        public string B { get; set; } = "";
        public bool Expected { get; set; }
    }

    public class Program
    {
        private static TestVectors LoadTestVectors()
        {
            var scriptDir = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) ?? ".";
            var vectorsPath = Path.Combine(scriptDir, "test-vectors.json");

            if (!File.Exists(vectorsPath))
            {
                vectorsPath = "tests/cross-sdk/test-vectors.json";
            }

            var json = File.ReadAllText(vectorsPath);
            var options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
            };
            return JsonSerializer.Deserialize<TestVectors>(json, options)
                ?? throw new Exception("Failed to parse test vectors");
        }

        private static (int passed, int failed) RunCanonicalizationTests(TestVectors vectors, bool verbose)
        {
            Console.WriteLine("\n=== JSON Canonicalization Tests ===");
            int passed = 0;
            int failed = 0;

            foreach (var test in vectors.Canonicalization?.Vectors ?? new List<CanonicalizationVector>())
            {
                try
                {
                    var result = AshCanonicalization.CanonicalizeJson(test.Input);
                    if (result == test.Expected)
                    {
                        passed++;
                        if (verbose)
                        {
                            Console.WriteLine($"  ✓ {test.Id}: {test.Description}");
                        }
                    }
                    else
                    {
                        failed++;
                        Console.WriteLine($"  ✗ {test.Id}: {test.Description}");
                        Console.WriteLine($"    Expected: {test.Expected}");
                        Console.WriteLine($"    Got:      {result}");
                    }
                }
                catch (Exception e)
                {
                    failed++;
                    Console.WriteLine($"  ✗ {test.Id}: {test.Description}");
                    Console.WriteLine($"    Error: {e.Message}");
                }
            }

            Console.WriteLine($"\nCanonicalization: {passed} passed, {failed} failed");
            return (passed, failed);
        }

        private static (int passed, int failed) RunUrlencodedTests(TestVectors vectors, bool verbose)
        {
            Console.WriteLine("\n=== URL-Encoded Canonicalization Tests ===");
            int passed = 0;
            int failed = 0;

            foreach (var test in vectors.UrlencodedCanonicalization?.Vectors ?? new List<UrlencodedVector>())
            {
                try
                {
                    var result = AshCanonicalization.CanonicalizeUrlencoded(test.Input);
                    if (result == test.Expected)
                    {
                        passed++;
                        if (verbose)
                        {
                            Console.WriteLine($"  ✓ {test.Id}: {test.Description}");
                        }
                    }
                    else
                    {
                        failed++;
                        Console.WriteLine($"  ✗ {test.Id}: {test.Description}");
                        Console.WriteLine($"    Expected: {test.Expected}");
                        Console.WriteLine($"    Got:      {result}");
                    }
                }
                catch (Exception e)
                {
                    failed++;
                    Console.WriteLine($"  ✗ {test.Id}: {test.Description}");
                    Console.WriteLine($"    Error: {e.Message}");
                }
            }

            Console.WriteLine($"\nURL-Encoded: {passed} passed, {failed} failed");
            return (passed, failed);
        }

        private static (int passed, int failed) RunBindingTests(TestVectors vectors, bool verbose)
        {
            Console.WriteLine("\n=== Binding Normalization Tests ===");
            int passed = 0;
            int failed = 0;

            foreach (var test in vectors.BindingNormalization?.Vectors ?? new List<BindingVector>())
            {
                try
                {
                    var result = AshBinding.Normalize(test.Method, test.Path, test.Query);
                    if (result == test.Expected)
                    {
                        passed++;
                        if (verbose)
                        {
                            Console.WriteLine($"  ✓ {test.Id}: {test.Description}");
                        }
                    }
                    else
                    {
                        failed++;
                        Console.WriteLine($"  ✗ {test.Id}: {test.Description}");
                        Console.WriteLine($"    Expected: {test.Expected}");
                        Console.WriteLine($"    Got:      {result}");
                    }
                }
                catch (Exception e)
                {
                    failed++;
                    Console.WriteLine($"  ✗ {test.Id}: {test.Description}");
                    Console.WriteLine($"    Error: {e.Message}");
                }
            }

            Console.WriteLine($"\nBinding: {passed} passed, {failed} failed");
            return (passed, failed);
        }

        private static (int passed, int failed) RunTimingSafeTests(TestVectors vectors, bool verbose)
        {
            Console.WriteLine("\n=== Timing-Safe Comparison Tests ===");
            int passed = 0;
            int failed = 0;

            foreach (var test in vectors.TimingSafeEqual?.Vectors ?? new List<TimingSafeVector>())
            {
                try
                {
                    var result = AshCrypto.TimingSafeEqual(test.A, test.B);
                    if (result == test.Expected)
                    {
                        passed++;
                        if (verbose)
                        {
                            Console.WriteLine($"  ✓ {test.Id}: a=\"{test.A}\", b=\"{test.B}\"");
                        }
                    }
                    else
                    {
                        failed++;
                        Console.WriteLine($"  ✗ {test.Id}: a=\"{test.A}\", b=\"{test.B}\"");
                        Console.WriteLine($"    Expected: {test.Expected}");
                        Console.WriteLine($"    Got:      {result}");
                    }
                }
                catch (Exception e)
                {
                    failed++;
                    Console.WriteLine($"  ✗ {test.Id}");
                    Console.WriteLine($"    Error: {e.Message}");
                }
            }

            Console.WriteLine($"\nTiming-Safe: {passed} passed, {failed} failed");
            return (passed, failed);
        }

        public static int Main(string[] args)
        {
            bool verbose = args.Contains("--verbose") || args.Contains("-v");
            string? category = null;

            for (int i = 0; i < args.Length - 1; i++)
            {
                if (args[i] == "--category" || args[i] == "-c")
                {
                    category = args[i + 1];
                    break;
                }
            }

            Console.WriteLine(new string('=', 60));
            Console.WriteLine("ASH Cross-SDK Test Vector Runner - .NET");
            Console.WriteLine(new string('=', 60));

            TestVectors vectors;
            try
            {
                vectors = LoadTestVectors();
            }
            catch (Exception e)
            {
                Console.WriteLine($"ERROR: {e.Message}");
                return 1;
            }

            int totalPassed = 0;
            int totalFailed = 0;

            var categories = new Dictionary<string, Func<TestVectors, bool, (int, int)>>
            {
                ["canonicalization"] = RunCanonicalizationTests,
                ["urlencoded"] = RunUrlencodedTests,
                ["binding"] = RunBindingTests,
                ["timing"] = RunTimingSafeTests
            };

            if (category != null)
            {
                if (categories.TryGetValue(category, out var func))
                {
                    var (p, f) = func(vectors, verbose);
                    totalPassed += p;
                    totalFailed += f;
                }
                else
                {
                    Console.WriteLine($"Unknown category: {category}");
                    Console.WriteLine($"Available: {string.Join(", ", categories.Keys)}");
                    return 1;
                }
            }
            else
            {
                foreach (var func in categories.Values)
                {
                    var (p, f) = func(vectors, verbose);
                    totalPassed += p;
                    totalFailed += f;
                }
            }

            Console.WriteLine();
            Console.WriteLine(new string('=', 60));
            Console.WriteLine($"TOTAL: {totalPassed} passed, {totalFailed} failed");
            Console.WriteLine(new string('=', 60));

            return totalFailed > 0 ? 1 : 0;
        }
    }
}
