using Arctium.Cryptography.Ciphers.StreamCiphers;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Binary;
using Arctium.Tests.Core;
using Arctium.Tests.Core.Attributes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Tests.Cryptography.Ciphers
{
    [TestsClass]
    internal class AEAD_CHACHA20_POLY1305_Tests
    {
        public AEAD_CHACHA20_POLY1305_Tests()
        { }

        [TestMethod]
        public List<TestResult> rfc7539_Tests()
        {
            var res = new List<TestResult>();

            foreach (var t in rfc7439_Tests)
            {
                AEAD_CHACHA20_POLY1305 aead = new AEAD_CHACHA20_POLY1305(t.Key);

                byte[] ciphertext = new byte[t.Plaintext.Length];
                byte[] tag = new byte[16];

                aead.AuthenticatedEncryption(t.IV, 0, t.IV.Length,
                    t.Plaintext, 0, t.Plaintext.Length,
                    t.AAD, 0, t.AAD.Length,
                    ciphertext, 0,
                    tag, 0);

                res.Add(new TestResult("poly1305_chacha20_aead", MemOps.Memcmp(tag, t.ExpectedTag) && MemOps.Memcmp(ciphertext, t.ExpectedCiphertext)));
            }

            return res;
        }

        static List<Test> rfc7439_Tests = new List<Test>
        {
            new Test(BinConverter.FromString("4c616469657320616e642047656e746c" +
                "656d656e206f662074686520636c6173" +
                "73206f66202739393a20496620492063" +
                "6f756c64206f6666657220796f75206f" +
                "6e6c79206f6e652074697020666f7220" +
                "746865206675747572652c2073756e73" +
                "637265656e20776f756c642062652069" +
                "742e"),
                BinConverter.FromString("50515253c0c1c2c3c4c5c6c7"),
                BinConverter.FromString("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
                BinConverter.FromString("070000004041424344454647"),
                BinConverter.FromString(
                "d31a8d34648e60db7b86afbc53ef7ec2" +
                "a4aded51296e08fea9e2b5a736ee62d6" +
                "3dbea45e8ca9671282fafb69da92728b" +
                "1a71de0a9e060b2905d6a5b67ecd3b36" +
                "92ddbd7f2d778b8c9803aee328091b58" +
                "fab324e4fad675945585808b4831d7bc" +
                "3ff4def08e4b7a9de576d26586cec64b" +
                "6116"),
                BinConverter.FromString("1ae10b594f09e26a7e902ecbd0600691"))
        };

        class Test
        {
            public byte[] Plaintext;
            public byte[] AAD;
            public byte[] Key;
            public byte[] IV;
            public byte[] ExpectedCiphertext;
            public byte[] ExpectedTag;

            public Test(byte[] plaintext, byte[] aad, byte[] key, byte[] iv,
                byte[] expectedCiphertext, byte[] expectedTag)
            {
                Plaintext = plaintext;
                AAD = aad;
                Key = key;
                IV = iv;
                ExpectedCiphertext = expectedCiphertext;
                ExpectedTag = expectedTag;
            }
        }


    }
}
