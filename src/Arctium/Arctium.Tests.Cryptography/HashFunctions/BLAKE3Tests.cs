using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Binary;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Tests.Core;
using Arctium.Tests.Core.Attributes;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Hashes = Arctium.Cryptography.HashFunctions.Hashes;

namespace Arctium.Tests.Cryptography.HashFunctions
{
    [TestsClass]
    public class BLAKE3Tests
    {
        public static List<HashFunctionTest> Short;

        static BLAKE3Tests()
        {
            Short = new List<HashFunctionTest>();

            LoadFromFile();
        }

        public static TestResult[] Run()
        {
            HashFunctionTest[] tests = LoadFromFile();
            List<TestResult> results = new List<TestResult>();
            Hashes.BLAKE3 blake3 = new Hashes.BLAKE3();

            foreach (var test in tests)
            {
                blake3.HashBytes(test.InputBytes);
                byte[] result = blake3.HashFinal();

                results.Add(new TestResult()
                {
                    Name = string.Format("BLAKE3 / input_len: {0}", test.InputBytes.Length),
                    Success = MemOps.Memcmp(result, test.ExpectedResultHash)
                });

                blake3.Reset();
            }

            return results.ToArray();
        }

        private static HashFunctionTest[] LoadFromFile()
        {
            string[] lines = File.ReadAllText(Files.HashFunctions.Blake3TestVectors).Split("\r\n");
            List<HashFunctionTest> tests = new List<HashFunctionTest>();

            for (int i = 0; i < lines.Length; i++)
            {
                if (!lines[i].Trim().StartsWith("\"input_len")) continue;

                int inputLength = int.Parse(lines[i].Split(':')[1].Trim('\"',','));
                string expectedHashAsString = lines[i + 1].Split(':')[1].Trim(' ', '\"').TrimEnd('\"',',').Substring(0, 64);

                byte[] expectedHash = BinConverter.FromString(expectedHashAsString);
                byte[] input = new byte[inputLength];

                for (int j = 0; j < inputLength; j++)
                {
                    input[j] = (byte)(j % 251);
                }

                Short.Add(new HashFunctionTest()
                {
                    ExpectedResultHash = expectedHash,
                    InputBytes = input,
                    Name = $"BLAKE3 / BLAKE3TestVectors.txt / InputLen: {input.Length}"
                }); ;
            }

            return tests.ToArray();
        }

        [TestMethod]
        public List<TestResult> BLAKE3_ShortTests()
        {
            List<TestResult> results = new List<TestResult>();

            results.AddRange(ExecuteHashFunctionTests.RunTests(new BLAKE3(), BLAKE3Tests.Short));

            return results;
        }
    }
}
