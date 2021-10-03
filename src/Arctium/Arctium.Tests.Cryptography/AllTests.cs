using Arctium.Tests.Core;
using Arctium.Tests.Cryptography.Ciphers;
using Arctium.Tests.Cryptography.HashFunctions;
using System.Collections.Generic;

namespace Arctium.Tests.Cryptography
{
    public class AllTests
    {
        public static TestResult[] RunShortTests()
        {
            List<TestResult> results = new List<TestResult>();

            results.AddRange(SHA3_Tests.Run());
            results.AddRange(BLAKE3Tests.Run());
            results.AddRange(BLAKE2b_512Tests.Run());
            results.AddRange(ThreefishTests.Run());
            results.AddRange(Skein_Tests.Run());
            results.AddRange(JHTests.Run());

            return results.ToArray();
        }

        public static TestResult[] RunLongTests()
        {
            List<TestResult> results = new List<TestResult>();

            results.AddRange(JHTests.RunLongTests());

            return results.ToArray();
        }
    }
}
