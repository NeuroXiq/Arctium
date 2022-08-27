using Arctium.Cryptography.Ciphers.BlockCiphers;
using Arctium.Shared.Helpers;
using Arctium.Tests.Core;
using Arctium.Tests.Core.Attributes;
using Arctium.Tests.Core.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Tests.Cryptography.Ciphers
{
    [TestsClass]
    internal class AEAD_AES_128
    {
        public AEAD_AES_128()
        {

        }

        [TestMethod]
        public List<TestResult> AES_GCM_Decrypt128()
        {
            return new List<TestResult>();
        }

        [TestMethod]
        public List<TestResult> AES_GCM_Decrypt192()
        {
            List<TestResult> results = new List<TestResult>();

            return results;
        }

        [TestMethod]
        public List<TestResult> AES_GCM_Decrypt256()
        {
            List<TestResult> results = new List<TestResult>();

            return results;
        }

        [TestMethod]
        public List<TestResult> AES_GCM_Encrypt128_NIST()
        {
            List<TestResult> results = new List<TestResult>();

            var input = MapEncrypt(Files.Ciphers.AES_GCM_Encrypt128);

            foreach (var test in input)
            {
                results.Add(Encrypt(test, nameof(AES_GCM_Encrypt128_NIST)));
            }

            return results;
        }

        [TestMethod]
        public List<TestResult> AES_GCM_Encrypt192()
        {
            List<TestResult> results = new List<TestResult>();

            return results;
        }

        [TestMethod]
        public List<TestResult> AES_GCM_Encrypt256()
        {
            List<TestResult> results = new List<TestResult>();

            return results;
        }

        TestResult Encrypt(TestEncrypt e, string tname)
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

        static List<TestEncrypt> MapEncrypt(string filename)
        {
            TestVectorFileParser<TestEncrypt> p = new Core.Utils.TestVectorFileParser<TestEncrypt>();
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

        public class TestEncrypt
        {
            public int Count;
            public byte[] Key;
            public byte[] IV;
            public byte[] PT;
            public byte[] AAD;
            public byte[] CT;
            public byte[] Tag;
        }
    }
}
