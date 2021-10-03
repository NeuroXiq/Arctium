

using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Binary;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Tests.Core;
using System.Collections.Generic;
using System.IO;

namespace Arctium.Tests.Cryptography.HashFunctions
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

    static class SHA3_Helper
    {
        public static HashFunctionTest[] LoadFromTestVectorsFile(string fileName)
        {
            // TODO: now this test vectors are with 'Copy' option (always copied to test runner project).
            //Consider to do not copy and use existing files from cryptography project
            string[] lines = File.ReadAllText(Files.GetFullPath("/HashFunctions/TestVectors/SHA3/" + fileName)).Split("\r\n");

            List<HashFunctionTest> tests = new List<HashFunctionTest>();

            for (int i = 0; i < lines.Length; i++)
            {
                if (!lines[i].StartsWith("Len")) continue;

                int length = int.Parse(lines[i].Split(' ')[2]);
                string inputBytesAsString = lines[i + 1].Split(' ')[2];
                string expectedHashAsString = lines[i + 2].Split(' ')[2];

                byte[] expectedHash = BinConverter.FromString(expectedHashAsString);
                byte[] input;

                if (length > 0)
                {
                    input = BinConverter.FromString(inputBytesAsString);
                }
                else
                {
                    input = new byte[0];
                }

                tests.Add(new HashFunctionTest()
                {
                    InputBytes = input,
                    ExpectedResultHash = expectedHash
                });
            }

            return tests.ToArray();
        }
    }
}
