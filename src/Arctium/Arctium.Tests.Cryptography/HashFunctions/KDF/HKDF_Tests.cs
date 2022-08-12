using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Cryptography.HashFunctions.KDF;
using Arctium.Cryptography.HashFunctions.MAC;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Binary;
using Arctium.Tests.Core;
using Arctium.Tests.Core.Attributes;
using System;
using System.Collections.Generic;
using System.IO;

namespace Arctium.Tests.Cryptography.HashFunctions.KDF
{
    [TestsClass]
    internal class HKDF_Tests
    {
        public HKDF_Tests() { }

        static HKDF_Tests()
        {
            LoadRFCTest();
            LoadVectorsGeneratedFromNetFrameworkTest();
        }

        [TestMethod]
        public List<TestResult> hkdf_vectors_netframework()
        {
            var result = new List<TestResult>();
            var hkdf = new HKDF(new HMAC(new SHA2_256(), new byte[0], 0, 0));

            foreach (var test in NetFrameworkTestsVectors)
            {
                byte[] prkout = new byte[32];
                byte[] generatedHKDF = new byte[test.OutputLength];
                hkdf.Extract(test.Salt, test.IKM, prkout);
                hkdf.Expand(prkout, test.Info, generatedHKDF, test.OutputLength);

                result.Add(new TestResult(test.TestName, MemOps.Memcmp(generatedHKDF, test.OKM)));
            }

            return result;
        }

        static void LoadVectorsGeneratedFromNetFrameworkTest()
        {
            /*
             KEY=CB
             SALT=19
             INFO=DC
             OUTLEN=1
             OUTPUT=73
            */

            var lines = File.ReadAllLines(Files.HashFunctions.HKDF_Sha256_Vectors);
            List<HKDFTest> tests = new List<HKDFTest>();

            for (int i = 0; i < lines.Length; i++)
            {
                var line = lines[i];
                if (string.IsNullOrEmpty(line) || (line[0] == '#') || !line.StartsWith("KEY")) continue;

                byte[] key = BinConverter.FromString( lines[i + 0].Split("=")[1]);
                byte[] salt = BinConverter.FromString(lines[i + 1].Split("=")[1]);
                byte[] info = BinConverter.FromString( lines[i + 2].Split("=")[1]);
                byte[] output = BinConverter.FromString( lines[i + 4].Split("=")[1]);

                tests.Add(new HKDFTest($"hkdf-netframework-vectors (keylen={key.Length})", "sha256", key, salt, info, null, output, output.Length));

                i += 4;
            }

            NetFrameworkTestsVectors = tests;
        }

        [TestMethod]
        public List<TestResult> HKDF_Vectors_from_rfc5868()
        {
            List<TestResult> results = new List<TestResult>();
            var sha1 = new HKDF(new HMAC(new SHA1(), new byte[0], 0, 0));
            var sha256 = new HKDF(new HMAC(new SHA2_256(), new byte[0], 0, 0));

            byte[] sha1PrkOut = new byte[20];
            byte[] sha256PrkOut = new byte[32];

            foreach (var test in RFCTests)
            {
                byte[] output = new byte[test.OutputLength];

                if (test.HashName == "sha1")
                {
                    sha1.Extract(test.Salt, test.IKM, sha1PrkOut);
                    sha1.Expand(sha1PrkOut, test.Info, output, test.OutputLength);
                }
                else
                {
                    sha256.Extract(test.Salt, test.IKM, sha256PrkOut);
                    sha256.Expand(sha256PrkOut, test.Info, output, test.OutputLength);
                }
                
                
                results.Add(new TestResult(test.TestName, MemOps.Memcmp(output, test.OKM)));
            }

            return results;
        }

        private static void LoadRFCTest()
        {
            RFCTests = new List<HKDFTest>()
            {
                new HKDFTest("rfc-case1",
                "sha256",
                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                "000102030405060708090a0b0c",
                "f0f1f2f3f4f5f6f7f8f9",
                "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
                42),
                new HKDFTest(
                "rfc-case2",
                "sha256",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
                    "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f" + 
                    "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
                
                    "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" + 
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf" + 
                "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf" + 
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeef" + 
                "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
                
                "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c" + 
                "59045a99cac7827271cb41c65e590e09" +
                "da3275600c2f09b8367793a9aca3db71" +
                "cc30c58179ec3e87c14c01d5c1f3434f" +
                "1d87",
                82),
                new HKDFTest(
                "rfc-case3",
                "sha256",
                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                "",
                "",
                "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
                42),
                new HKDFTest(
                "rfc-case4",
                "sha1",
                "0b0b0b0b0b0b0b0b0b0b0b",
                "000102030405060708090a0b0c",
                "f0f1f2f3f4f5f6f7f8f9",
                "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243",
                "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896",
                42),
                new HKDFTest(
                "rfc-case5",
                "sha1",
                "000102030405060708090a0b0c0d0e0f" +
          "101112131415161718191a1b1c1d1e1f" +
          "202122232425262728292a2b2c2d2e2f" +
          "303132333435363738393a3b3c3d3e3f" +
          "404142434445464748494a4b4c4d4e4f",

                "606162636465666768696a6b6c6d6e6f"+
                "707172737475767778797a7b7c7d7e7f"+
                "808182838485868788898a8b8c8d8e8f"+
                "909192939495969798999a9b9c9d9e9f"+
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",

                "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"+
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"+
                "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"+
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"+
                "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",

                "8adae09a2a307059478d309b26c4115a224cfaf6",

                "0bd770a74d1160f7c9f12cd5912a06eb"+
                "ff6adcae899d92191fe4305673ba2ffe"+
                "8fa3f1a4e5ad79f3f334b3b202b2173c"+
                "486ea37ce3d397ed034c7f9dfeb15c5e"+
                "927336d0441f4c4300e2cff0d0900b52"+
                "d3b4",
                82),
                new HKDFTest(
                "rfc-case6",
                "sha1",
                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                "",
                "",
                "da8c8a73c7fa77288ec6f5e7c297786aa0d32d01",
                "0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918",
                42),
                new HKDFTest(
                "rfc-case7",
                "sha1",
                "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
                "0000000000000000000000000000000000000000",
                "",
                "2adccada18779e7c2077ad2eb19d3f3e731385dd",
                "2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48",
                42),
            };
        }

        static List<HKDFTest> RFCTests;
        static List<HKDFTest> NetFrameworkTestsVectors;

        class HKDFTest
        {
            public string HashName;
            public byte[] IKM;
            public byte[] Salt;
            public byte[] Info;
            public int OutputLength;
            public string TestName;
            public byte[] PRK;
            public byte[] OKM;

            public HKDFTest(string testName, string hashName, string ikm, string salt, string info, string prk, string okm, int outputLength)
                : this(testName,
                      hashName,
                      BinConverter.FromString(ikm),
                      BinConverter.FromString(salt),
                      BinConverter.FromString(info),
                      BinConverter.FromString(prk),
                      BinConverter.FromString(okm),
                      outputLength)
            { }

            public HKDFTest(string testName, string hashName, byte[] ikm, byte[] salt, byte[] info,
                byte[] prk, byte[] okm, int outputLength)
            {
                TestName = testName;
                IKM = ikm;
                Salt = salt;
                Info = info;
                OutputLength = outputLength;
                HashName = hashName;
                PRK = prk;
                OKM = okm;
            }
        }
    }
}
