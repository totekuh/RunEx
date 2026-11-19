using System;
using System.IO;
using System.Reflection;

public class TestRunner
{
    static int passed = 0;
    static int failed = 0;
    static int total = 0;

    static void AssertEqual(string expected, string actual, string testName)
    {
        total++;
        if (expected == actual) {
            passed++;
            Console.WriteLine("  PASS  " + testName);
        } else {
            failed++;
            Console.WriteLine("  FAIL  " + testName);
            Console.WriteLine("        expected: " + (expected ?? "(null)"));
            Console.WriteLine("        actual:   " + (actual ?? "(null)"));
        }
    }

    static void AssertContains(string haystack, string needle, string testName)
    {
        total++;
        if (haystack != null && haystack.Contains(needle)) {
            passed++;
            Console.WriteLine("  PASS  " + testName);
        } else {
            failed++;
            Console.WriteLine("  FAIL  " + testName);
            Console.WriteLine("        expected to contain: " + needle);
            Console.WriteLine("        actual: " + (haystack ?? "(null)"));
        }
    }

    static void AssertNotContains(string haystack, string needle, string testName)
    {
        total++;
        if (haystack == null || !haystack.Contains(needle)) {
            passed++;
            Console.WriteLine("  PASS  " + testName);
        } else {
            failed++;
            Console.WriteLine("  FAIL  " + testName);
            Console.WriteLine("        expected NOT to contain: " + needle);
            Console.WriteLine("        actual: " + haystack);
        }
    }

    static void AssertTrue(bool condition, string testName)
    {
        total++;
        if (condition) {
            passed++;
            Console.WriteLine("  PASS  " + testName);
        } else {
            failed++;
            Console.WriteLine("  FAIL  " + testName);
        }
    }

    static void Reset()
    {
        RunExMainClass.Verbose = false;
    }

    static string SafeRunExMain(string[] args)
    {
        try {
            return RunExMainClass.RunExMain(args);
        } catch (Exception e) {
            return "EXCEPTION:" + e.GetType().Name + ":" + e.Message;
        }
    }

    // ================================================================
    // U-01: --version
    // ================================================================
    static void Test_Version()
    {
        Reset();
        AssertEqual("RunEx v2.1.2", SafeRunExMain(new string[]{"--version"}), "U-01a: --version");
        Reset();
        AssertEqual("RunEx v2.1.2", SafeRunExMain(new string[]{"-V"}), "U-01b: -V alias");
    }

    // ================================================================
    // U-02: --help short-circuits
    // ================================================================
    static void Test_Help()
    {
        Reset();
        TextWriter original = Console.Out;
        StringWriter capture = new StringWriter();
        Console.SetOut(capture);
        string result = SafeRunExMain(new string[]{"--help"});
        Console.SetOut(original);
        AssertEqual("", result, "U-02a: --help returns empty string");
        AssertContains(capture.ToString(), "RunEx", "U-02b: --help writes help to console");

        Reset();
        capture = new StringWriter();
        Console.SetOut(capture);
        result = SafeRunExMain(new string[]{"-h"});
        Console.SetOut(original);
        AssertEqual("", result, "U-02c: -h alias");

        Reset();
        capture = new StringWriter();
        Console.SetOut(capture);
        result = SafeRunExMain(new string[]{"/?"});
        Console.SetOut(original);
        AssertEqual("", result, "U-02d: /? alias");
    }

    // ================================================================
    // U-03: Too few args
    // ================================================================
    static void Test_TooFewArgs()
    {
        Reset();
        AssertContains(SafeRunExMain(new string[]{}), "Not enough arguments", "U-03a: zero args");
        Reset();
        AssertContains(SafeRunExMain(new string[]{"user"}), "Not enough arguments", "U-03b: one arg");
        Reset();
        AssertContains(SafeRunExMain(new string[]{"user", "pass"}), "Not enough arguments", "U-03c: two args");
    }

    // ================================================================
    // U-04: Missing flag value
    // ================================================================
    static void Test_MissingFlagValue()
    {
        Reset();
        AssertContains(SafeRunExMain(new string[]{"user", "pass", "cmd", "-l"}),
            "Invalid arguments", "U-04a: dangling -l");
        Reset();
        AssertContains(SafeRunExMain(new string[]{"user", "pass", "cmd", "-t"}),
            "Invalid arguments", "U-04b: dangling -t");
        Reset();
        AssertContains(SafeRunExMain(new string[]{"user", "pass", "cmd", "-f"}),
            "Invalid arguments", "U-04c: dangling -f");
        Reset();
        AssertContains(SafeRunExMain(new string[]{"user", "pass", "cmd", "-r"}),
            "Invalid arguments", "U-04d: dangling -r");
        Reset();
        AssertContains(SafeRunExMain(new string[]{"user", "pass", "cmd", "-d"}),
            "Invalid arguments", "U-04e: dangling -d");
    }

    // ================================================================
    // U-05: Invalid logon type
    // ================================================================
    static void Test_InvalidLogonType()
    {
        Reset();
        AssertContains(SafeRunExMain(new string[]{"user", "pass", "cmd", "-l", "kerberos"}),
            "Invalid logon type", "U-05a: bad alias");
        Reset();
        AssertContains(SafeRunExMain(new string[]{"user", "pass", "cmd", "-l", "99"}),
            "Invalid logon type", "U-05b: bad numeric");
    }

    // ================================================================
    // U-06: Valid logon aliases accepted
    // ================================================================
    static void Test_ValidLogonAliases()
    {
        string[] aliases = {"interactive", "network", "batch", "service",
                            "cleartext", "newcreds", "netonly", "remote", "cached"};
        foreach (string alias in aliases) {
            Reset();
            string result = SafeRunExMain(new string[]{"user", "pass", "cmd", "-l", alias});
            AssertNotContains(result, "Invalid logon type", "U-06: alias '" + alias + "' accepted");
        }
    }

    // ================================================================
    // U-07: Valid logon numerics accepted
    // ================================================================
    static void Test_ValidLogonNumerics()
    {
        string[] nums = {"2", "3", "4", "5", "7", "8", "9", "10", "11"};
        foreach (string num in nums) {
            Reset();
            string result = SafeRunExMain(new string[]{"user", "pass", "cmd", "-l", num});
            AssertNotContains(result, "Invalid logon type", "U-07: numeric '" + num + "' accepted");
        }
    }

    // ================================================================
    // U-08: Invalid CreateProcess function
    // ================================================================
    static void Test_InvalidFunction()
    {
        Reset();
        AssertContains(SafeRunExMain(new string[]{"user", "pass", "cmd", "-f", "bogus"}),
            "Invalid createProcess function", "U-08a: bad alias");
        Reset();
        AssertContains(SafeRunExMain(new string[]{"user", "pass", "cmd", "-f", "9"}),
            "Invalid createProcess function", "U-08b: bad numeric");
    }

    // ================================================================
    // U-09: Valid CreateProcess function aliases
    // ================================================================
    static void Test_ValidFunctions()
    {
        string[] vals = {"asuser", "withtoken", "withlogon", "0", "1", "2"};
        foreach (string val in vals) {
            Reset();
            string result = SafeRunExMain(new string[]{"user", "pass", "cmd", "-f", val});
            AssertNotContains(result, "Invalid createProcess function",
                "U-09: function '" + val + "' accepted");
        }
    }

    // ================================================================
    // U-10: Invalid timeout
    // ================================================================
    static void Test_InvalidTimeout()
    {
        Reset();
        AssertContains(SafeRunExMain(new string[]{"user", "pass", "cmd", "-t", "abc"}),
            "Invalid process_timeout", "U-10a: non-numeric");
        Reset();
        AssertContains(SafeRunExMain(new string[]{"user", "pass", "cmd", "-t", "-1"}),
            "Invalid process_timeout", "U-10b: negative");
    }

    // ================================================================
    // U-11: Passthrough + remote mutually exclusive
    // ================================================================
    static void Test_PassthroughRemoteExclusive()
    {
        Reset();
        AssertContains(
            SafeRunExMain(new string[]{"user", "pass", "cmd", "-f", "2", "-P", "-r", "1.2.3.4:4444"}),
            "mutually exclusive", "U-11: -P + -r rejected");
    }

    // ================================================================
    // U-12: Invalid remote format
    // ================================================================
    static void Test_InvalidRemote()
    {
        Reset();
        AssertContains(SafeRunExMain(new string[]{"user", "pass", "cmd", "-r", "noport"}),
            "Invalid remote value", "U-12a: missing colon");
        Reset();
        AssertContains(SafeRunExMain(new string[]{"user", "pass", "cmd", "-r", "a:b:c"}),
            "Invalid remote value", "U-12b: too many colons");
    }

    // ================================================================
    // U-13: Valid remote format
    // ================================================================
    static void Test_ValidRemote()
    {
        Reset();
        string result = SafeRunExMain(new string[]{"user", "pass", "cmd", "-r", "10.0.0.1:4444"});
        AssertNotContains(result, "Invalid remote value", "U-13: valid host:port accepted");
    }

    // ================================================================
    // U-14: -- stops flag parsing
    // ================================================================
    static void Test_DoubleDashSeparator()
    {
        Reset();
        string result = SafeRunExMain(new string[]{
            "user", "pass", "-l", "2", "--", "cmd", "-l", "notaflag"});
        AssertNotContains(result, "Invalid logon type",
            "U-14: -l after -- treated as command arg, not flag");
    }

    // ================================================================
    // U-15: convertAttributeToString via reflection
    // ================================================================
    static void Test_ConvertAttributeToString()
    {
        MethodInfo method = typeof(AccessToken).GetMethod("convertAttributeToString",
            BindingFlags.NonPublic | BindingFlags.Static);
        if (method == null) {
            total++;
            failed++;
            Console.WriteLine("  FAIL  U-15: could not find convertAttributeToString via reflection");
            return;
        }

        string[] expected = {"Disabled", "Enabled Default", "Enabled", "Enabled|Enabled Default"};
        for (uint i = 0; i < 4; i++) {
            string result = (string)method.Invoke(null, new object[] { i });
            AssertEqual(expected[i], result, "U-15: attribute " + i);
        }
        string errResult = (string)method.Invoke(null, new object[] { (uint)99 });
        AssertEqual("Error", errResult, "U-15: unknown attribute returns Error");
    }

    // ================================================================
    // U-16: IntegrityLevel enum ordering (System > High > Medium > Low)
    // ================================================================
    static void Test_IntegrityLevelOrdering()
    {
        AssertTrue(AccessToken.IntegrityLevel.System > AccessToken.IntegrityLevel.High,
            "U-16a: System > High");
        AssertTrue(AccessToken.IntegrityLevel.High > AccessToken.IntegrityLevel.Medium,
            "U-16b: High > Medium");
        AssertTrue(AccessToken.IntegrityLevel.Medium > AccessToken.IntegrityLevel.Low,
            "U-16c: Medium > Low");
        AssertTrue(AccessToken.IntegrityLevel.Low > AccessToken.IntegrityLevel.Untrusted,
            "U-16d: Low > Untrusted");
        AssertTrue(AccessToken.IntegrityLevel.ProtectedProcess > AccessToken.IntegrityLevel.System,
            "U-16e: ProtectedProcess > System");
    }

    // ================================================================
    // U-17: IntegrityLevel enum values match RID constants
    // ================================================================
    static void Test_IntegrityLevelRIDValues()
    {
        AssertEqual("0", ((int)AccessToken.IntegrityLevel.Untrusted).ToString(),
            "U-17a: Untrusted == 0x0000");
        AssertEqual("4096", ((int)AccessToken.IntegrityLevel.Low).ToString(),
            "U-17b: Low == 0x1000");
        AssertEqual("8192", ((int)AccessToken.IntegrityLevel.Medium).ToString(),
            "U-17c: Medium == 0x2000");
        AssertEqual("12288", ((int)AccessToken.IntegrityLevel.High).ToString(),
            "U-17d: High == 0x3000");
        AssertEqual("16384", ((int)AccessToken.IntegrityLevel.System).ToString(),
            "U-17e: System == 0x4000");
        AssertEqual("20480", ((int)AccessToken.IntegrityLevel.ProtectedProcess).ToString(),
            "U-17f: ProtectedProcess == 0x5000");
        // Verify System RID distinct from High — the bug was >= High catching System
        AssertTrue((int)AccessToken.IntegrityLevel.System != (int)AccessToken.IntegrityLevel.High,
            "U-17g: System != High (distinct RIDs)");
    }

    // ================================================================
    // U-18: TOKEN_PRIVILEGES struct removed (compile-time check)
    // ================================================================
    static void Test_DeadTokenPrivilegesStructRemoved()
    {
        Type t = typeof(NativeMethods).GetNestedType("TOKEN_PRIVILEGES",
            BindingFlags.NonPublic | BindingFlags.Public);
        AssertTrue(t == null,
            "U-18: TOKEN_PRIVILEGES struct removed (only TOKEN_PRIVILEGES_2 should exist)");
        Type t2 = typeof(NativeMethods).GetNestedType("TOKEN_PRIVILEGES_2",
            BindingFlags.NonPublic | BindingFlags.Public);
        AssertTrue(t2 != null,
            "U-18b: TOKEN_PRIVILEGES_2 still exists");
    }

    // ================================================================
    // Main
    // ================================================================
    public static void Main(string[] args)
    {
        Console.WriteLine("RunEx Unit Tests");
        Console.WriteLine("================");
        Console.WriteLine();

        Test_Version();
        Test_Help();
        Test_TooFewArgs();
        Test_MissingFlagValue();
        Test_InvalidLogonType();
        Test_ValidLogonAliases();
        Test_ValidLogonNumerics();
        Test_InvalidFunction();
        Test_ValidFunctions();
        Test_InvalidTimeout();
        Test_PassthroughRemoteExclusive();
        Test_InvalidRemote();
        Test_ValidRemote();
        Test_DoubleDashSeparator();
        Test_ConvertAttributeToString();
        Test_IntegrityLevelOrdering();
        Test_IntegrityLevelRIDValues();
        Test_DeadTokenPrivilegesStructRemoved();

        Console.WriteLine();
        Console.WriteLine("================");
        Console.WriteLine(total + " tests: " + passed + " passed, " + failed + " failed");

        Environment.ExitCode = (failed > 0) ? 1 : 0;
    }
}
