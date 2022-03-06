using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Tests.Core;
using Arctium.Tests.Core.Attributes;
using System.Collections.Generic;

namespace Arctium.Tests.Cryptography.HashFunctions
{
    [TestsClass]
    public class SHA3_Tests
    {
        public static List<HashFunctionTest> Short224;
        public static List<HashFunctionTest> Short256;
        public static List<HashFunctionTest> Short384;
        public static List<HashFunctionTest> Short512;

        static SHA3_Tests()
        {
            Short224 = HashFunctionTestHelper.LoadTestsFromSLKatFile("SHA3-224", Files.HashFunctions.SHA3224ShortMsg);
            Short256 = HashFunctionTestHelper.LoadTestsFromSLKatFile("SHA3-256", Files.HashFunctions.SHA3256ShortMsg);
            Short384 = HashFunctionTestHelper.LoadTestsFromSLKatFile("SHA3-384", Files.HashFunctions.SHA3384ShortMsg);
            Short512 = HashFunctionTestHelper.LoadTestsFromSLKatFile("SHA3-512", Files.HashFunctions.SHA3512ShortMsg);

            Short224.AddRange(HashFunctionTestHelper.LoadTestsFromSLKatFile("SHA3-224", Files.HashFunctions.SHA3224LongMsg));
            Short256.AddRange(HashFunctionTestHelper.LoadTestsFromSLKatFile("SHA3-256", Files.HashFunctions.SHA3256LongMsg));
            Short384.AddRange(HashFunctionTestHelper.LoadTestsFromSLKatFile("SHA3-384", Files.HashFunctions.SHA3384LongMsg));
            Short512.AddRange(HashFunctionTestHelper.LoadTestsFromSLKatFile("SHA3-512", Files.HashFunctions.SHA3512LongMsg));
        }

        [TestMethod]
        public List<TestResult> SHA3_All_Tests()
        {
            List<TestResult> results = new List<TestResult>();

            results.AddRange(ExecuteHashFunctionTests.RunTests(new SHA3_224(), SHA3_Tests.Short224));
            results.AddRange(ExecuteHashFunctionTests.RunTests(new SHA3_256(), SHA3_Tests.Short256));
            results.AddRange(ExecuteHashFunctionTests.RunTests(new SHA3_384(), SHA3_Tests.Short384));
            results.AddRange(ExecuteHashFunctionTests.RunTests(new SHA3_512(), SHA3_Tests.Short512));

            return results;
        }
    }
}
