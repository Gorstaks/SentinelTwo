using System;
using System.Collections.Generic;
using System.Reflection;

namespace SentinelTwo.Tests
{
    // Minimal test framework (no packages; C# 5 compatible). Test classes end in "Tests" and expose
    // public static void methods whose names start with "Test". Classes ending in "IntegrationTests"
    // touch the live machine and run only with --integration.
    internal sealed class TestFailure : Exception
    {
        public TestFailure(string message) : base(message) { }
    }

    internal static class Assert
    {
        public static void True(bool condition, string message)
        {
            if (!condition) throw new TestFailure("expected true: " + message);
        }

        public static void False(bool condition, string message)
        {
            if (condition) throw new TestFailure("expected false: " + message);
        }

        public static void Equal(object expected, object actual, string message)
        {
            if (!Equals(expected, actual))
                throw new TestFailure(message + ": expected [" + expected + "] but was [" + actual + "]");
        }

        public static void Near(double expected, double actual, double tolerance, string message)
        {
            if (Math.Abs(expected - actual) > tolerance)
                throw new TestFailure(message + ": expected " + expected + " +/- " + tolerance + " but was " + actual);
        }
    }

    internal static class Runner
    {
        public static int Main(string[] args)
        {
            bool integration = Array.IndexOf(args, "--integration") >= 0;
            int passed = 0;
            List<string> failures = new List<string>();
            int skipped = 0;

            Type[] types = Assembly.GetExecutingAssembly().GetTypes();
            foreach (Type type in types)
            {
                if (type.Namespace != "SentinelTwo.Tests" || !type.Name.EndsWith("Tests", StringComparison.Ordinal)) continue;
                bool isIntegration = type.Name.EndsWith("IntegrationTests", StringComparison.Ordinal);
                if (isIntegration && !integration)
                {
                    skipped++;
                    continue;
                }

                MethodInfo[] methods = type.GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly);
                foreach (MethodInfo method in methods)
                {
                    if (!method.Name.StartsWith("Test", StringComparison.Ordinal) || method.ReturnType != typeof(void)) continue;
                    if (method.GetParameters().Length != 0) continue;

                    string name = type.Name + "." + method.Name;
                    try
                    {
                        method.Invoke(null, null);
                        passed++;
                        Console.WriteLine("PASS  " + name);
                    }
                    catch (TargetInvocationException ex)
                    {
                        string message = ex.InnerException == null ? ex.Message : ex.InnerException.Message;
                        failures.Add(name + ": " + message);
                        Console.WriteLine("FAIL  " + name + "  " + message);
                    }
                }
            }

            Console.WriteLine();
            Console.WriteLine("Passed: " + passed + "  Failed: " + failures.Count +
                              (integration ? "" : "  (integration tests skipped: " + skipped + "; pass --integration to run them)"));
            return failures.Count == 0 ? 0 : 1;
        }
    }
}
