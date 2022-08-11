using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Cryptography.HashFunctions.MAC;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Binary;
using Arctium.Tests.Core;
using Arctium.Tests.Core.Attributes;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Arctium.Tests.Cryptography.HashFunctions.MAC
{
    [TestsClass]
    internal class HMAC_Tests
    {
        [TestMethod]
        public List<TestResult> HMAC_SHA2_Tests()
        {
            HMAC sha224 = new HMAC(new SHA2_224(), new byte[1], 0, 1);
            HMAC sha256 = new HMAC(new SHA2_256(), new byte[1], 0, 1);
            HMAC sha384 = new HMAC(new SHA2_384(), new byte[1], 0, 1);
            HMAC sha512 = new HMAC(new SHA2_512(), new byte[1], 0, 1);
            HMAC sha1 = new HMAC(new SHA1(), new byte[1], 0, 1);

            byte[] result224 = new byte[28];
            byte[] result256 = new byte[32];
            byte[] result384 = new byte[48];
            byte[] result512 = new byte[64];
            byte[] result1 = new byte[64];

            List<TestResult> results = new List<TestResult>();
            int i = 0;

            foreach (var test in SHA2Tests)
            {
                i++;

                sha224.ChangeKey(test.Key);
                sha256.ChangeKey(test.Key);
                sha384.ChangeKey(test.Key);
                sha512.ChangeKey(test.Key);
                sha1.  ChangeKey(test.Key);

                sha224.ComputeHMAC(test.Data, result224);
                sha256.ComputeHMAC(test.Data, result256);
                sha384.ComputeHMAC(test.Data, result384);
                sha512.ComputeHMAC(test.Data, result512);
                sha1.ComputeHMAC(test.Data, result1);

                results.Add(new TestResult("hmac-sha224 (custom from hmac rfc) / " + i, MemOps.Memcmp(result224, test.Sha224)));
                results.Add(new TestResult("hmac-sha256 (custom from hmac rfc) / " + i, MemOps.Memcmp(result256, test.Sha256)));
                results.Add(new TestResult("hmac-sha384 (custom from hmac rfc) / " + i, MemOps.Memcmp(result384, test.Sha384)));
                results.Add(new TestResult("hmac-sha512 (custom from hmac rfc) / " + i, MemOps.Memcmp(result512, test.Sha512)));
            }

            return results;
        }

        [TestMethod]
        public List<TestResult> HMAC_SHA_NIST_TestVectors()
        {
            HMAC sha224 = new HMAC(new SHA2_224(), new byte[1], 0, 1);
            HMAC sha256 = new HMAC(new SHA2_256(), new byte[1], 0, 1);
            HMAC sha384 = new HMAC(new SHA2_384(), new byte[1], 0, 1);
            HMAC sha512 = new HMAC(new SHA2_512(), new byte[1], 0, 1);
            HMAC sha1 = new HMAC(new SHA1(), new byte[1], 0, 1);

            List<TestResult> results = new List<TestResult>();
            byte[] output = new byte[128];

            foreach (var test in NistTests)
            {
                switch (test.HashFuncName)
                {
                    case "sha1":       sha1.ChangeKey(test.Key);         sha1.ComputeHMAC(test.Data, output); break;
                    case "sha1-224": sha224.ChangeKey(test.Key); sha224.ComputeHMAC(test.Data, output); break;
                    case "sha1-256": sha256.ChangeKey(test.Key); sha256.ComputeHMAC(test.Data, output); break;
                    case "sha1-384": sha384.ChangeKey(test.Key); sha384.ComputeHMAC(test.Data, output); break;
                    case "sha1-512": sha512.ChangeKey(test.Key); sha512.ComputeHMAC(test.Data, output); break;
                }

                bool success = true;

                for (int i = 0; i < test.TruncateLength; i++)
                {
                    success &= output[i] == test.Result[i];
                }

                results.Add(new TestResult(test.TestName, success));
            }

            return results;
        }

        static HMAC_Tests()
        {
            LoadFromFile();
        }

        static void LoadFromFile()
        {
            var allLines = File.ReadAllLines(Files.HashFunctions.HMAC_NIST);
            string hashFuncName = null;
            List<HmacTest> tests = new List<HmacTest>();

            for (int i = 0; i < allLines.Length; i++)
            {
                var line = allLines[i].Trim();

                if (line.Length == 0 || line[0] == '#') continue;

                if (line.StartsWith("["))
                {
                    switch (line)
                    {
                        case "[L=20]": hashFuncName = "sha1";  break;
                        case "[L=28]": hashFuncName = "sha1-224"; break;
                        case "[L=32]": hashFuncName = "sha1-256"; break;
                        case "[L=48]": hashFuncName = "sha1-384"; break;
                        case "[L=64]": hashFuncName = "sha1-512"; break;
                        default: throw new System.Exception("parsing hmac_nist file test vectors");
                    }

                    continue;
                }

                if (line.StartsWith("Count"))
                {
                    int count = int.Parse(allLines[i + 0].Split("=")[1]);
                    int klen = int.Parse(allLines[i + 1].Split("=")[1]);
                    int tlen = int.Parse(allLines[i + 2].Split("=")[1]);
                    byte[] key = BinConverter.FromString(allLines[i + 3].Split("=")[1].Trim());
                    byte[] msg = BinConverter.FromString(allLines[i + 4].Split("=")[1].Trim());
                    byte[] mac = BinConverter.FromString(allLines[i + 5].Split("=")[1].Trim());

                    var testName = string.Format("HMAC / NIST / hash: {0}, count: {1}", hashFuncName, count);
                    var parsed = new HmacTest(key, msg, mac, tlen, testName, hashFuncName);

                    tests.Add(parsed);

                    i += 5;
                }
            }

            NistTests = tests;
        }

        static List<HmacTest> NistTests;

        static List<HmacTest> MD5Tests = new List<HmacTest>()
        {
            // new HmacTest(BinConverter.FromString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), "Hi There", "9294727a3638bb1c13f48ef8158bfc9d"),
            //new HmacTest("Jefe", "what do ya want for nothing?", "750c783e6ab0b503eaa86e310a5db738"),
            //new HmacTest(
            //    BinConverter.FromString("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            //    Enumerable.Range(1, 50).Select(x => (byte)0xDD).ToArray(), // 50 times '0xDD'
            //    BinConverter.FromString("750c783e6ab0b503eaa86e310a5db738"))
        };

        static List<HmacSha2Test> SHA2Tests = new List<HmacSha2Test>()
        {
            new HmacSha2Test("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                "4869205468657265",
                "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22",
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
                "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
                "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"),
            new HmacSha2Test(
                "4a656665",
                "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
                "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44",
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
                "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
                "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"),
            new HmacSha2Test(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                "7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea",
                "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
                "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27",
                "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"),
            new HmacSha2Test(
                "0102030405060708090a0b0c0d0e0f10111213141516171819",
                "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
                "6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a",
                "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
                "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb",
                "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd"),
            new HmacSha2Test(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaa",
                "54657374205573696e67204c61726765" +
                "72205468616e20426c6f636b2d53697a" +
                "65204b6579202d2048617368204b6579" +
                "204669727374",
                "95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e",
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
                "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952",
                "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"),
            new HmacSha2Test(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                  "aaaaaa",
                "54686973206973206120746573742075" +
                "73696e672061206c6172676572207468" +
                "616e20626c6f636b2d73697a65206b65" +
                "7920616e642061206c61726765722074" +
                "68616e20626c6f636b2d73697a652064" +
                "6174612e20546865206b6579206e6565" +
                "647320746f2062652068617368656420" +
                "6265666f7265206265696e6720757365" +
                "642062792074686520484d414320616c" +
                "676f726974686d2e",
                "3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1",
                "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
                "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e",
                "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58"),
            //new HmacSha2Test(
            //    "",
            //    "",
            //    "",
            //    "",
            //    "",
            //    ""),
            //new HmacSha2Test(
            //    "",
            //    "",
            //    "",
            //    "",
            //    "",
            //    ""),
        };

        class HmacSha2Test
        {
            public byte[] Key;
            public byte[] Data;
            public byte[] Sha224;
            public byte[] Sha256;
            public byte[] Sha384;
            public byte[] Sha512;

            public HmacSha2Test(string key, string data, string sha224, string sha256, string sha384, string sha512)
            {
                Key = BinConverter.FromString(key);
                Data = BinConverter.FromString(data);
                Sha224 = BinConverter.FromString(sha224);
                Sha256 = BinConverter.FromString(sha256);
                Sha384 = BinConverter.FromString(sha384);
                Sha512 = BinConverter.FromString(sha512);
            }
        }

        class HmacTest
        {
            public byte[] Key;
            public byte[] Data;
            public byte[] Result;
            public int TruncateLength;
            public string TestName;
            public string HashFuncName;

            public HmacTest(byte[] key, byte[] data, byte[] result, int truncateLength, string testName, string hashFuncName)
            {
                Key = key;
                Data = data;
                Result = result;
                TruncateLength = truncateLength;
                TestName = testName;
                HashFuncName = hashFuncName;
            }
        }
    }
}
