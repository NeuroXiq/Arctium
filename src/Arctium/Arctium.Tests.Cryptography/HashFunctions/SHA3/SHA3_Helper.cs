using Arctium.Shared.Helpers.Binary;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Arctium.Tests.Cryptography.HashFunctions.SHA3
{
    static class SHA3_Helper
    {
        public static HashFunctionTest[] LoadFromTestVectorsFile(string fileName)
        {
            // TODO: now this test vectors are with 'Copy' option (always copied to test runner project).
            //Consider to do not copy and use existing files from cryptography project
            string[] lines = File.ReadAllText("./HashFunctions/SHA3/TestVectors/" + fileName).Split("\r\n");

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
