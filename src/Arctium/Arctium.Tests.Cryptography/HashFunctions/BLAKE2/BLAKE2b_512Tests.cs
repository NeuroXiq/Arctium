using Arctium.Shared.Helpers.Binary;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Tests.Core;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Hashes = Arctium.Cryptography.HashFunctions.Hashes;

namespace Arctium.Tests.Cryptography.HashFunctions.BLAKE2
{
    public class BLAKE2b_512Tests
    {
        public static TestResult[] Run()
        {
            List<TestResult> results = new List<TestResult>();
            HashFunctionTest[] tests = Load();
            Hashes.BLAKE2b_512 blake2b512 = new Hashes.BLAKE2b_512();

            foreach(HashFunctionTest test in tests)
            {
                blake2b512.HashBytes(test.InputBytes);
                byte[] result = blake2b512.HashFinal();

                results.Add(new TestResult()
                {
                    Name = string.Format("BLAKE2B_512 / TestVectors /Input Length {0}", test.InputBytes.Length),
                    Success = MemOps.Memcmp(result, test.ExpectedResultHash)
                });

                blake2b512.Reset();
            }

            return results.ToArray();
        }

        private static HashFunctionTest[] Load()
        {
            string[] lines = File.ReadLines("./HashFunctions/BLAKE2/Blake2b_512_TestVectors.txt").ToArray();
            List<HashFunctionTest> tests = new List<HashFunctionTest>();

            for (int i = 0; i < lines.Length; i++)
            {
                if (!lines[i].Trim().StartsWith("\"in")) continue;

                string inputAsString = lines[i].Split(':')[1].Trim(' ', '"', ',');
                string expectedHashAsString = lines[i + 2].Split(':')[1].Trim(' ', '"', ',');

                byte[] input;
                byte[] expectedHash = BinConverter.FromString(expectedHashAsString);

                if (inputAsString.Length > 0)
                {
                    input = BinConverter.FromString(inputAsString);
                }
                else
                {
                    input = new byte[0];
                }

                tests.Add(new HashFunctionTest()
                {
                    ExpectedResultHash = expectedHash,
                    InputBytes = input
                });
            }

            return tests.ToArray();
        }
    }
}
