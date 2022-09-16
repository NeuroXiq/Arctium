using Arctium.Shared.Interfaces;
using System.IO;

namespace Arctium.Cryptography.HashFunctions.Hashes
{
    /// <summary>
    /// Base class for hash functions
    /// </summary>
    public abstract class HashFunction
    {
        /// <summary>
        /// Output hash size in bits
        /// </summary>
        public int HashSizeBits { get; private set; }

        /// <summary>
        /// Output hash size in bytes
        /// </summary>
        public int HashSizeBytes { get { return HashSizeBits / 8; } }

        /// <summary>
        /// Input block size in bits
        /// </summary>
        public int InputBlockSizeBits { get; private set; }

        /// <summary>
        /// Input block size in bytes 
        /// </summary>
        public int InputBlockSizeBytes { get { return InputBlockSizeBits / 8; } }

        protected long LoadedBytes;

        public HashFunction(int inputBlockSize, int hashSizeBits)
        {
            HashSizeBits = hashSizeBits;
            InputBlockSizeBits = inputBlockSize;
            LoadedBytes = 0;
        }

        /// <summary>
        /// Apply hash transform
        /// </summary>
        /// <param name="buffer">Bytes to hash</param>
        public abstract void HashBytes(byte[] buffer);

        /// <summary>
        /// Apply hash transform
        /// </summary>
        /// <param name="stream">Input stream </param>
        /// <returns>Hash value of all bytes readed from the stream</returns>
        public abstract long HashBytes(Stream stream);

        /// <summary>
        /// Apply hash transform
        /// </summary>
        /// <param name="buffer">Bytes to hash</param>
        /// <param name="offset">Start position</param>
        /// <param name="length">Length of bytes to transform</param>
        public abstract void HashBytes(byte[] buffer, long offset, long length);

        public abstract byte[] HashFinal();

        public abstract void Reset();
    }
}
