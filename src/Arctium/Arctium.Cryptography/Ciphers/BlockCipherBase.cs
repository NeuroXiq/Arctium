using Arctium.Cryptography.Ciphers.BlockCiphers.Shared;
using System.IO;

namespace Arctium.Cryptography.Ciphers
{
    /// <summary>
    /// Base class for all block ciphers. 
    /// </summary>
    public abstract class BlockCipherBase
    {
        /// <summary>
        /// Length of the input block in bits
        /// </summary>
        public int InputBlockSize { get; protected set; }
        public byte[] Key { get; private set; }
        public BlockCipherMode CipherMode { get; protected set; }

        public BlockCipherBase(byte[] key, int inputBlockSize, BlockCipherMode blockCipherMode)
        {
            InputBlockSize = inputBlockSize;
            CipherMode = blockCipherMode;
            Key = key;
        }

        public abstract int Encrypt(byte[] inputBuffer, int inputOffset, int inputLength, byte[] outputBuffer, int outputOffset);

        public abstract int Decrypt(byte[] inputBuffer, int inputOffset, int inputLength, byte[] outputBuffer, int outputOffset);

        public abstract int Encrypt(Stream inputStream, Stream outputStream);

        public abstract int Decrypt(Stream inputStream, Stream outputStream);
    }
}
