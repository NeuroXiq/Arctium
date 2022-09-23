using Arctium.Cryptography.Ciphers.BlockCiphers;
using Arctium.Cryptography.Ciphers.BlockCiphers.ModeOfOperation;
using Arctium.Shared.Helpers;
using Arctium.Tests.Core;
using Arctium.Tests.Core.Attributes;
using System.Collections.Generic;
using System.Linq;

namespace Arctium.Tests.Cryptography.Ciphers
{
    [TestsClass]
    internal class AEAD_AES_128_CCM_Tests
    {
        [TestMethod]
        public List<TestResult> NIST_TEST_AES_CCM_Encrypt_Decrypt()
        {
            List<TestResult> res = new List<TestResult>();

            foreach (var t in NIST_TESTS)
            {
                AEAD aead = new CCMMode(new AES(t.Key), t.Tag.Length);
                byte[] ciphertext = new byte[t.PT.Length];
                byte[] authTag = new byte[t.Tag.Length];

                aead.AuthenticatedEncryption(
                    t.IV, 0, t.IV.Length,
                    t.PT, 0, t.PT.Length,
                    t.AAD, 0, t.AAD.Length,
                    ciphertext, 0,
                    authTag, 0);

                res.Add(new TestResult("aead aes 128 encrypt", MemOps.Memcmp(authTag, t.Tag) && MemOps.Memcmp(t.CT, ciphertext)));
            }

            return res;
        }

        static List<AEADTest> NIST_TESTS = new List<AEADTest>()
        {
            AEADTest.CreateEncrypt(
                "404142434445464748494a4b4c4d4e4f",
                "10111213141516",
                "0001020304050607",
                "20212223",
                "7162015b",
                "4dac255d"),
            AEADTest.CreateEncrypt(
                "404142434445464748494a4b4c4d4e4f",
                "1011121314151617",
                "000102030405060708090a0b0c0d0e0f",
                "202122232425262728292a2b2c2d2e2f",
                "d2a1f0e051ea5f62081a7792073d593d",
                "1fc64fbfaccd"),
            AEADTest.CreateEncrypt(
                "404142434445464748494a4b4c4d4e4f",
                "101112131415161718191a1b",
                "000102030405060708090a0b0c0d0e0f10111213",
                "202122232425262728292a2b2c2d2e2f3031323334353637",
                "e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5",
                "484392fbc1b09951"),
            Example4()

        };

        static AEADTest Example4()
        {
            byte[] a = new byte[524288 / 8];

            for (int i = 0; i < a.Length; i++)
            {
                a[i] = (byte)i;
            }

            var x = AEADTest.CreateEncrypt(
                "404142434445464748494a4b4c4d4e4f",
                "101112131415161718191a1b1c",
                "01",
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
                "69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72",
                 "b4ac6bec93e8598e7f0dadbcea5b");

            x.AAD = a;

            return x;
        }

        class CCMTest
        {
            public byte[] K;
            public byte[] N;
            public byte[] A;
            public byte[] P;
            public byte[] ExpectedOutput;
            public int TLEN;

            public CCMTest(string k, string n, string a, string p, string expOut, int tlen)
            {
                //K = BinConverter.FromString(k);
                //N = BinConverter.FromString(n);
                //A = BinConverter.FromString(a);
                //P = BinConverter.FromString(p);
                //ExpectedOutput = BinConverter.FromString(expOut);
                //TLEN = tlen;
            }
        }
    }
}
