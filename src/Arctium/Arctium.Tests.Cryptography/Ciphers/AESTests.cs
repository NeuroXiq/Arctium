using Arctium.Cryptography.Ciphers.BlockCiphers;
using Arctium.Shared.Helpers;
using Arctium.Tests.Core;
using Arctium.Tests.Core.Attributes;
using System;
using System.Collections.Generic;
using System.Text;

namespace Arctium.Tests.Cryptography.Ciphers
{
    [TestsClass]
    public class AESTests
    {
        public AESTests()
        { }

        [TestMethod]
        public List<TestResult> SelfEncrypDecrypt128() { return SelfEncryptDecrypt(128); }

        [TestMethod]
        public List<TestResult> SelfEncryptDecrypt192() { return SelfEncryptDecrypt(192); }

        [TestMethod]
        public List<TestResult> SelfEncryptDecrypt256() { return SelfEncryptDecrypt(256); }

        [TestMethod]
        public List<TestResult> EncryptDecryptFIPS197Vectors()
        {
            Tuple<byte[], byte[], byte[]>[] keyInputOutput = new Tuple<byte[], byte[], byte[]>[]
                {
                    new Tuple<byte[], byte[], byte[]> (
                        new byte[] { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c },
                        new byte[] { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 },
                        new byte[] { 0x39, 0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,0xdc,0x11,0x85, 0x97, 0x19, 0x6a, 0x0b,0x32 }
                        ),
                    new Tuple<byte[], byte[], byte[]> (
                        new byte[] {  0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f, },
                        new byte[] { 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff, },
                        new byte[] { 0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a, }
                        ),
                    new Tuple<byte[], byte[], byte[]>(
                        new byte[] { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17, },
                        new byte[] { 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff, },
                        new byte[] { 0xdd,0xa9,0x7c,0xa4,0x86,0x4c,0xdf,0xe0,0x6e,0xaf,0x70,0xa0,0xec,0x0d,0x71,0x91, }
                        ),
                    new Tuple<byte[], byte[], byte[]>(
                        new byte[] { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f, },
                        new byte[] { 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff, },
                        new byte[] { 0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89, }
                        )
                };

            byte[] outp = new byte[16];
            byte[] decrOutput = new byte[16];
            List<TestResult> results = new List<TestResult>();

            for (int i = 0; i < keyInputOutput.Length; i++)
            {
                byte[] key = keyInputOutput[i].Item1;
                byte[] input = keyInputOutput[i].Item2;
                byte[] output = keyInputOutput[i].Item3;

                AES aes = new AES(key, BlockCipherMode.ECB);

                aes.Encrypt(input, 0, outp, 0, 16);
                aes.Decrypt(outp, 0, decrOutput, 0, 16);

                string tname = $"AES / Key: {key.Length * 8}, tupleNo: {i}";
                bool okEncrypt = MemOps.Memcmp(output, outp);
                bool okDecrypt = MemOps.Memcmp(input, decrOutput);

                if (!okEncrypt) tname += " / Fail encrypt";
                if (!okDecrypt) tname += " / Fail decrypt";

                results.Add(new TestResult(tname, okEncrypt && okDecrypt));
            }

            return results;
        }

        private List<TestResult> SelfEncryptDecrypt(int keySize)
        {
            List<TestResult> results = new List<TestResult>();
            string tname = "";
            int blocksCount = 8;
            byte[] key = GenerateKey(keySize / 8);
            byte[] input = new byte[blocksCount * 16];
            byte[] output = new byte[blocksCount * 16];
            byte[] decrOutput = new byte[blocksCount * 16];

            for (int i = 0; i < input.Length; i++) input[i] = (byte)i;

            AES aes = new AES(key, BlockCipherMode.ECB);

            for (int i = 0; i < blocksCount; i++)
            {
                tname = $"AES / EncryptDecrypt / KeySize: {keySize}, blockCount: {i}";
                MemOps.Memset(input, 0, input.Length, 0);
                MemOps.Memset(output, 0, input.Length, 0);

                try
                {
                    aes.Encrypt(input, 0, output, 0, blocksCount * 16);
                    aes.Decrypt(output, 0, decrOutput, 0, 16 * blocksCount);
                    bool success = MemOps.Memcmp(input, decrOutput);

                    results.Add(new TestResult(tname, success));
                }
                catch (Exception e)
                {
                    results.Add(new TestResult(tname, e, false));
                }
            }

            return results;
        }

        private byte[] GenerateKey(int keyLen)
        {
            byte[] k = new byte[keyLen];
            for (int i = 0; i < k.Length; i++) k[i] = (byte)i;

            return k;
        }
    }
}
