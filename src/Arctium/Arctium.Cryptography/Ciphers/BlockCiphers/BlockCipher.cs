using System;

namespace Arctium.Cryptography.Ciphers.BlockCiphers
{
    public unsafe abstract class BlockCipher
    {
        public int InputBlockLengthBits { get; private set;}

        public readonly int InputBlockLengthBytes;

        public BlockCipherMode BlockCipherMode { get; private set; }

        protected byte[] key;
        protected byte[] initializationVector;

        protected BlockCipher(byte[] key, byte[] initializationVector, int inputBlockLengthBits, BlockCipherMode mode)
        {
            InputBlockLengthBits = inputBlockLengthBits;
            InputBlockLengthBytes = InputBlockLengthBits / 8;
            BlockCipherMode = mode;
            
            this.key = key;
            this.initializationVector = initializationVector;
        }

        public BlockCipher(byte[] key, int inputBlockLength, BlockCipherMode mode) : this (key, null, inputBlockLength, mode) { }

        public abstract long Encrypt(byte[] input, long offset, byte[] output, long outputOffset, long length);

        public abstract long Decrypt(byte[] input, long offset, byte[] output, long outputOffset, long length);
    }
}
