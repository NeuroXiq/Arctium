using System;
using Arctium.Cryptography.Ciphers.BlockCiphers.Algorithms;
using Arctium.Cryptography.Ciphers.Exceptions;

namespace Arctium.Cryptography.Ciphers.BlockCiphers
{
    public unsafe class Camellia : BlockCipher
    {
        private CamelliaAlgorithm.State state;
        delegate void ProcessBlockDelegate(CamelliaAlgorithm.State state, byte* input, byte* output);
        ProcessBlockDelegate encryptBlock;
        ProcessBlockDelegate decryptBlock;

        /// <summary>
        /// Camellia block ciphers with 128/192/256 key sized.
        /// Input block size 16 bytes
        /// </summary>
        /// <param name="key">16/24/32 bytes key</param>
        public Camellia(byte[] key) : base(key, 128)
        {
            if (key == null || (key.Length != 16 && key.Length != 24 && key.Length != 32)) throw new InvalidKeyLengthException("invalid key length");
            state = CamelliaAlgorithm.Init(key);

            if (key.Length == 16)
            {
                encryptBlock = CamelliaAlgorithm.EncryptBlock;
                decryptBlock = CamelliaAlgorithm.DecryptBlock;
            }
            else
            {
                encryptBlock = CamelliaAlgorithm.EncryptBlock192_256;
                decryptBlock = CamelliaAlgorithm.DecryptBlock192_256;
            }
        }

        public override long Decrypt(byte[] input, long offset, byte[] output, long outputOffset, long length)
        {
            fixed(byte* inputPtr = &input[offset], outputPtr = &output[0])
            {
                byte* inputP = inputPtr, outputP = outputPtr;

                for (long i = 0; i < length; i += 16)
                {
                    decryptBlock(state, inputP, outputP);
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
                    encryptBlock(state, inputP, outputP);
                    inputP += 16;
                    outputP += 16;
                }
            }

            return length;
        }
    }
}
