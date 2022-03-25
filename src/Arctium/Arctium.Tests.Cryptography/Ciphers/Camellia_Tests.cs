using Arctium.Cryptography.Ciphers.BlockCiphers;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Binary;
using Arctium.Tests.Core;
using Arctium.Tests.Core.Attributes;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Arctium.Tests.Cryptography.Ciphers
{
    [TestsClass]
    internal class Camellia_Tests
    {
        [TestMethod]
        public List<TestResult> Camellia128() => RunTests(Files.Ciphers.Camellia128);

        [TestMethod]
        public List<TestResult> Camellia192() => RunTests(Files.Ciphers.Camellia192);

        [TestMethod]
        public List<TestResult> Camellia256() => RunTests(Files.Ciphers.Camellia256);

        List<TestResult> RunTests(string testVectorFileName)
        {
            var allLines = File.ReadAllLines(testVectorFileName)
                .Where(line => !string.IsNullOrEmpty(line))
                .Select(line => line.Split(':').Select(s => s.Trim()).ToArray())
                .ToArray();

            List<TestVector> vectors = new List<TestVector>();
            TestVector current = new TestVector(null, null);

            for (int i = 0; i < allLines.Length; i++)
            {
                if (allLines[i][0].StartsWith("K No."))
                {
                    string keyAsString = allLines[i][1];
                    byte[] key = BinConverter.FromString(keyAsString, " ");

                    current = new TestVector($"{allLines[i][0]} ({key.Length * 8} bits)/ ", key);
                    vectors.Add(current);

                    continue;
                }

                byte[] plaintext = BinConverter.FromString(allLines[i][1], " ");
                byte[] ciphertext = BinConverter.FromString(allLines[i + 1][1], " ");

                current.PlaintextCiphertext.Add(new byte[][] { plaintext, ciphertext });
                i++;
            }

            List<TestResult> results = new List<TestResult>();

            foreach (var vector in vectors)
            {
                byte[] output = new byte[16];
                Camellia c = new Camellia(vector.Key);

                for (int i = 0; i < vector.PlaintextCiphertext.Count; i++)
                {
                    var pc = vector.PlaintextCiphertext[i];
                    var plain = pc[0];
                    var expectedCiphertext = pc[1];

                    c.Encrypt(plain, 0, output, 0, plain.Length);

                    bool success = MemOps.Memcmp(output, expectedCiphertext);

                    results.Add(new TestResult(vector.Name + $"ENCRYPT / {i}", success));
                }
            }

            return results;
        }


        class TestVector
        {
            public string Name;
            public byte[] Key;
            public List<byte[][]> PlaintextCiphertext;

            public TestVector(string name, byte[] key)
            {
                Name = name;
                Key = key;
                PlaintextCiphertext = new List<byte[][]>();
            }
        }
    }
}
