using Arctium.Cryptography.Ciphers.BlockCiphers.Shared;
using System;

namespace Arctium.Cryptography.Ciphers.BlockCiphers
{
    public unsafe abstract class BlockCipher
    {
        public int InputBlockLength { get; private set;}

        public BlockCipherMode BlockCipherMode { get; private set; }

        protected byte[] key;

        protected BlockCipher(byte[] key,int inputBlockLength, BlockCipherMode mode)
        {

            InputBlockLength = inputBlockLength;
            BlockCipherMode = mode;
            this.key = key;
        }

        public abstract long Encrypt(byte[] input, long offset, byte[] output, long outputOffset, long length);

        public abstract long Decrypt(byte[] input, long offset, byte[] output, long outputOffset, long length);

    }
}
