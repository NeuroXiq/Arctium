

using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Tests.Core;
using System.Collections.Generic;

namespace Arctium.Tests.Cryptography.HashFunctions.SHA3
{
    public class SHA3_Tests
    {
        public static TestResult[] Run()
        {
            List<TestResult> results = new List<TestResult>();

            RunTests(new SHA3_224(), "SHA3_224", "SHA3_224LongMsg.rsp", results);
            RunTests(new SHA3_224(), "SHA3_224", "SHA3_224ShortMsg.rsp", results);
            RunTests(new SHA3_256(), "SHA3_256", "SHA3_256LongMsg.rsp", results);
            RunTests(new SHA3_256(), "SHA3_256", "SHA3_256ShortMsg.rsp", results);
            RunTests(new SHA3_384(), "SHA3_384", "SHA3_384LongMsg.rsp", results);
            RunTests(new SHA3_384(), "SHA3_384", "SHA3_384ShortMsg.rsp", results);
            RunTests(new SHA3_512(), "SHA3_512", "SHA3_512LongMsg.rsp", results);
            RunTests(new SHA3_512(), "SHA3_512", "SHA3_512ShortMsg.rsp", results);

            return results.ToArray();
        }

        private static void RunTests(HashFunction sha, string algoName, string testVectorFileName, List<TestResult> results)
        {
            HashFunctionTest[] tests = SHA3_Helper.LoadFromTestVectorsFile(testVectorFileName);

            foreach (HashFunctionTest test in tests)
            {
                sha.HashBytes(test.InputBytes);
                var result = sha.HashFinal();

                results.Add(new TestResult()
                {
                    Name = string.Format("{0} / TestVectors ({1}) / Len {2}, ",
                        algoName, testVectorFileName, test.InputBytes.Length * 8),
                    Success = MemOps.Memcmp(result, test.ExpectedResultHash)
                });

                sha.Reset();
            }
        }
    }
}
