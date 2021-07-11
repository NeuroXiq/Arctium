using Arctium.Cryptography.Ciphers.BlockCiphers.Algorithms;
using Arctium.Cryptography.Ciphers.Exceptions;

namespace Arctium.Cryptography.Ciphers.BlockCiphers
{
    public abstract class Threefish
    {
        public int BlockSize { get; private set; }
        protected ThreefishAlgorithm.Context context;

        protected Threefish(byte[] key)
        {
            int blockSize = key.Length * 8;

            if (blockSize != 256 && blockSize != 512 && blockSize != 1024)
            {
                throw new InvalidBlockLengthException("Invalid block length for Threefish Block cipher. Allowed values: 256, 512, 1024");
            }

            Initialise(key);
        }

        public abstract void Encrypt(byte[] input, long inputOffset, byte[] output, long outputOffset, byte[] tweak);
        public abstract void Decrypt(byte[] input, long inputOffset, byte[] output, long outputOffset, byte[] tweak);

        private void Initialise(byte[] key)
        {
            context = ThreefishAlgorithm.Initialise(key);
        }
    }
}
