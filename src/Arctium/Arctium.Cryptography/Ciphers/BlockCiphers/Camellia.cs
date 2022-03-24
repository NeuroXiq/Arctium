using System;
using Arctium.Cryptography.Ciphers.BlockCiphers.Algorithms;
using Arctium.Cryptography.Ciphers.Exceptions;

namespace Arctium.Cryptography.Ciphers.BlockCiphers
{
    public unsafe class Camellia : BlockCipher
    {
        private CamelliaAlgorithm.State state;

        public Camellia(byte[] key) : base(key, 128)
        {
            if (key == null || (key.Length != 16 && key.Length != 24 && key.Length != 32)) throw new InvalidKeyLengthException("invalid key length");
            state = CamelliaAlgorithm.Init(key);
        }

        public override long Decrypt(byte[] input, long offset, byte[] output, long outputOffset, long length)
        {
            fixed(byte* inputPtr = &input[offset], outputPtr = &output[0])
            {
                byte* inputP = inputPtr, outputP = outputPtr;

                for (long i = 0; i < length; i += 16)
                {
                    CamelliaAlgorithm.DecryptBlock(state, inputP, outputP);
                    inputP += 16;
                    outputP += 16;
                }
            }

            return length;
        }

        public override long Encrypt(byte[] input, long offset, byte[] output, long outputOffset, long length)
        {
            fixed(byte* inputPtr = &input[offset], outputPtr = &output[0])
            {
                byte* inputP = inputPtr, outputP = outputPtr;

                for (long i = 0; i < length; i += 16)
                {
                    CamelliaAlgorithm.EncryptBlock(state, inputP, outputP);
                    inputP += 16;
                    outputP += 16;
                }
            }

            return length;
        }
    }
}
