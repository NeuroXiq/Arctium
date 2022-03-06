using System;
using Arctium.Cryptography.Ciphers.BlockCiphers.Algorithms;

namespace Arctium.Cryptography.Ciphers.BlockCiphers
{
    public unsafe class AES : BlockCipher
    {
        public AESAlgorithm.Context context;

        private readonly int roundsCount;

        public AES(byte[] key) : base(key, 128)
        {
            if (key.Length != 16 && key.Length != 24 && key.Length != 32) throw new ArgumentException("key len invalid");
            if (key.Length == 16) roundsCount = 10;
            else if (key.Length == 24) roundsCount = 12;
            else roundsCount = 14;

            context = AESAlgorithm.Initialize(key); 
        }

        public override long Decrypt(byte[] input, long offset, byte[] output, long outputOffset, long length)
        {
            fixed (byte* ip = &input[offset], op = &output[outputOffset])
            {
                for (long i = 0; i < length; i += 16)
                {
                    AESAlgorithm.DecryptSingleBlock(context, ip, i, op, i, roundsCount);
                }
            }

            return length;
        }

        public override long Encrypt(byte[] input, long offset, byte[] output, long outputOffset, long length)
        {
            fixed (byte* ip = &input[offset], op = &output[outputOffset])
            {
                for (long i = 0; i < length; i += 16)
                {
                    AESAlgorithm.EncryptSingleBlock(context, ip, i, op, i, roundsCount);
                }
            }

            return length;
        }
    }
}
