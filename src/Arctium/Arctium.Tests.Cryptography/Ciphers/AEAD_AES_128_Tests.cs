using Arctium.Cryptography.Ciphers.BlockCiphers;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Binary;
using Arctium.Tests.Core;
using Arctium.Tests.Core.Attributes;
using Arctium.Tests.Core.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Tests.Cryptography.Ciphers
{
    [TestsClass]
    internal class AEAD_AES_128_Tests
    {
        public AEAD_AES_128_Tests()
        {

        }

        [TestMethod]
        public List<TestResult> AES_GCM_Decrypt192()
        {
            var r = new List<TestResult>();
            var vectors192 = MapDecrypt(Files.Ciphers.AES_GCM_Decrypt192);
            foreach (var t in vectors192) { r.Add(Decrypt(t, "aes gcm 192 decrypt / ")); }

            return r;
        }

        [TestMethod]
        public List<TestResult> AES_GCM_Decrypt256()
        {
            List<TestResult> r = new List<TestResult>();

            var vectors256 = MapDecrypt(Files.Ciphers.AES_GCM_Decrypt256);
            foreach (var t in vectors256) { r.Add(Decrypt(t, "aes gcm 256 decrypt / ")); }

            return r;
        }

        [TestMethod]
        public List<TestResult> AES_GCM_Encrypt192()
        {
            List<TestResult> results = new List<TestResult>();
            var vectors192 = MapEncrypt(Files.Ciphers.AES_GCM_Encrypt192);

            foreach (var test in vectors192) { results.Add(Encrypt(test, "aes gcm 192 encrypt")); }

            return results;
        }

        [TestMethod]
        public List<TestResult> AES_GCM_Encrypt256()
        {
            List<TestResult> results = new List<TestResult>();
            var vectors256 = MapEncrypt(Files.Ciphers.AES_GCM_Encrypt256);
            foreach (var test in vectors256) { results.Add(Encrypt(test, "aes gcm 256 encrypt")); }

            return results;
        }

        [TestMethod]
        public List<TestResult> AES_GCM_Decrypt128()
        {
            List<TestResult> r = new List<TestResult>();

            var vectors128 = MapDecrypt(Files.Ciphers.AES_GCM_Decrypt128);
            foreach (var t in vectors128) { r.Add(Decrypt(t, "aes gcm 128 decrypt / ")); }

            return r;
        }

        [TestMethod]
        public List<TestResult> AES_GCM_Encrypt128_NIST()
        {
            List<TestResult> results = new List<TestResult>();
            var vectors128 = MapEncrypt(Files.Ciphers.AES_GCM_Encrypt128);
            
            foreach (var test in vectors128) { results.Add(Encrypt(test, "aes gcm 128 encrypt")); }

            return results;
        }

        TestResult Decrypt(AEADTest e, string tname)
        {
            AEAD aead = new GaloisCounterMode(new AES(e.Key), e.Tag.Length);

            byte[] plain = new byte[e.CT.Length];
            //byte[] authTag = new byte[e.Tag.Length];
            bool tagValid;

            aead.AuthenticatedDecryption(e.IV, 0, e.IV.Length,
                e.CT, 0, e.CT.Length,
                e.AAD, 0, e.AAD.Length,
                plain, 0,
                e.Tag, 0,
                out tagValid);

            tname = string.Format("{0}, Count: {1}, klen: {2}, ivlen: {3}, ptlen: {4}, aadlen: {5}, taglen: {6}",
                tname,
                e.Count,
                e.Key.Length * 8,
                e.IV.Length * 8,
                e.PT != null ? e.PT.Length * 8 : -1,
                e.AAD.Length * 8,
                e.Tag.Length * 8);

            if (!tagValid && e.ExpectedDecryptionFail)
            {
                return new TestResult(tname, true);
            }
            else if (!tagValid)
            {
                return new TestResult(tname + " invalid tag", false);
            }
            else if (!MemOps.Memcmp(plain, e.PT))
            {
                return new TestResult(tname + " plaintext invalid", false);
            }

            return new TestResult(tname, true);

        }

        TestResult Encrypt(AEADTest e, string tname)
        {
            AEAD aead = new GaloisCounterMode(new AES(e.Key), e.Tag.Length);

            byte[] ciphOutput = new byte[e.PT.Length];
            byte[] authTag = new byte[e.Tag.Length];

            aead.AuthenticatedEncryption(e.IV, 0, e.IV.Length,
                e.PT, 0, e.PT.Length,
                e.AAD, 0, e.AAD.Length,
                ciphOutput, 0,
                authTag, 0);

            bool ciphOk = MemOps.Memcmp(ciphOutput, e.CT);
            bool tagOk = MemOps.Memcmp(authTag, e.Tag);
            tname = string.Format("{0}, Count: {1}, klen: {2}, ivlen: {3}, ptlen: {4}, aadlen: {5}, taglen: {6}",
                tname,
                e.Count,
                e.Key.Length * 8,
                e.IV.Length * 8,
                e.PT.Length * 8,
                e.AAD.Length * 8,
                e.Tag.Length * 8);

            if (!ciphOk)
            {
                return new TestResult(tname + ", ciphertext fail ", false);
            }
            else if (!tagOk)
            {
                return new TestResult(tname + ", authtag fail ", false);
            }
            else return new TestResult(tname, true);
        }

        static List<AEADTest> MapDecrypt(string filename)
        {
            var allLines = File.ReadAllLines(filename);
            List<AEADTest> tests = new List<AEADTest>();

            /*
             
Count = 14
Key = 3b19d8a4795b52e6dc4f8fd3c091c05a65c8f3cddc665ab473e6144011ae54a4
IV = 23744265b6865b99bed99f11
CT = 
AAD = 
Tag = b7a67b6068d2b22c1b26f795ee1701be
FAIL             */


            for (int i = 0; i < allLines.Length; i++)
            {
                if (!allLines[i].StartsWith("Count")) continue;

                var t = new AEADTest();
                t.Count = int.Parse(allLines[i].Split("=")[1].Trim());
                t.Key = BinConverter.FromString(allLines[i + 1].Split("=")[1].Trim());
                t.IV = BinConverter.FromString(allLines[i + 2].Split("=")[1].Trim());
                t.CT = BinConverter.FromString(allLines[i + 3].Split("=")[1].Trim());
                t.AAD = BinConverter.FromString(allLines[i + 4].Split("=")[1].Trim());
                t.Tag = BinConverter.FromString(allLines[i + 5].Split("=")[1].Trim());

                if (allLines[i + 6].Trim() == "FAIL")
                {
                    t.ExpectedDecryptionFail = true;
                }
                else
                {
                    t.PT = BinConverter.FromString(allLines[i + 6].Split("=")[1].Trim());
                }

                i += 6;

                tests.Add(t);
            }

            return tests;
        }

        static List<AEADTest> MapEncrypt(string filename)
        {
            TestVectorFileParser<AEADTest> p = new Core.Utils.TestVectorFileParser<AEADTest>();
            p.StartingPointInFileMapPropertyName("Count");

            p.Map<int>("Count", (test, v) => test.Count = v);
            p.Map<byte[]>("Key", (test, v) => test.Key = v);
            p.Map<byte[]>("IV", (test, v) => test.IV = v);
            p.Map<byte[]>("PT", (test, v) => test.PT = v);
            p.Map<byte[]>("AAD", (test, v) => test.AAD = v);
            p.Map<byte[]>("CT", (test, v) => test.CT = v);
            p.Map<byte[]>("Tag", (test, v) => test.Tag = v);

            p.IgnoreStartWith("[");
            p.IgnoreStartWith("#");

            return p.Parse(filename);
        }
    }
}
