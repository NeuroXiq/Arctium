﻿using Arctium.Cryptography.Ciphers.BlockCiphers.Algorithms;

namespace Arctium.Cryptography.Ciphers.BlockCiphers
{
    public unsafe class AES_256 : BlockCipher
    {
        public AESAlgorithm.Context context;

        public AES_256(byte[] key) : base(key, 128)
        {
            context = AESAlgorithm.Initialize(key);
        }

        public override long Decrypt(byte[] input, long offset, byte[] output, long outputOffset, long length)
        {
            fixed (uint* k = &context.ExpandedKey[0])
            fixed (byte* ip = &input[offset], op = &output[outputOffset])
            {
                byte* ipp = ip;
                byte* opp = op;
                for (long i = 0; i < length; i += 16)
                {
                    AESOptimizedAlgorithm.DecryptBlock256(k, ipp, opp);
                    ipp += 16;
                    opp += 16;
                }
            }

            return length;
        }

        public override long Encrypt(byte[] input, long offset, byte[] output, long outputOffset, long length)
        {
            fixed (uint* key = &context.ExpandedKey[0])
            fixed (byte* ip = &input[offset], op = &output[outputOffset])
            {
                byte* ipp = ip;
                byte* opp = op;

                for (long i = 0; i < length; i += 16)
                {
                    AESOptimizedAlgorithm.EncryptBlock256(key, ipp, opp);
                    ipp += 16;
                    opp += 16;
                }
            }

            return length;
        }
    }
}
