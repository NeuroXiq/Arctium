using System;
using System.Collections.Generic;
using System.Text;
using Arctium.Cryptography.Ciphers.BlockCiphers.Algorithms;

namespace Arctium.Cryptography.Ciphers.BlockCiphers
{
    public unsafe class AES_128 : AES
    {
        public AES_128(byte[] key, BlockCipherMode mode) : base (key, 128, mode) { }


        public override long Encrypt(byte[] input, long offset, byte[] output, long outputOffset, long length)
        {
            fixed(byte* b = &input[0], o = &output[0])
            {
                AESAlgorithm.EncryptSingleBlock(context, b, offset, o, outputOffset, 10);
            }

            return 0;
        }


        public override long Decrypt(byte[] input, long offset, byte[] output, long outputOffset, long length)
        {
            fixed(byte* b = &input[0], o = &output[0])
            {
                AESAlgorithm.DecryptSingleBlock(context, b, offset, o, outputOffset, 10);
            }

            return 0;
        }
    }
}
