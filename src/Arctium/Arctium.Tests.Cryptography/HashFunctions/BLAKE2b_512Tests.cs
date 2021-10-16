using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Binary;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Tests.Core;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Hashes = Arctium.Cryptography.HashFunctions.Hashes;

namespace Arctium.Tests.Cryptography.HashFunctions
{
    public class BLAKE2b_512Tests
    {
        public static List<HashFunctionTest> Short;

        static BLAKE2b_512Tests()
        {
            Short = new List<HashFunctionTest>();

            LoadFromFile();
        }

        private static void LoadFromFile()
        {
            string[] lines = File.ReadLines(Files.HashFunctions.Blake2b512TestVectors).ToArray();
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

                Short.Add(new HashFunctionTest()
                {
                    ExpectedResultHash = expectedHash,
                    InputBytes = input,
                    Name = $"BLAKE2B512 / InputLen: {input.Length}"
                });
            }
        }
    }
}
