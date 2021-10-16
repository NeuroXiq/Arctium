using System.Collections.Generic;

namespace Arctium.Tests.Cryptography.HashFunctions
{
    public static class SHA3_Tests
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
    }
}
