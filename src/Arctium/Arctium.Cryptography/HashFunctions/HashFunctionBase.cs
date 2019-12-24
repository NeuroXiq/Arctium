using System.IO;

namespace Arctium.Cryptography.HashFunctions
{
    /// <summary>
    /// Base class for all hash function.
    /// </summary>
    public abstract class HashFunctionBase
    {
        const int KBit = 1024;

        /// <summary>
        /// Input block size in bits
        /// </summary>
        public int InputBlockLength { get; private set; }

        /// <summary>
        /// Output hash size in bits.
        /// </summary>
        public int HashSize { get; private set; }

        /// <summary>
        /// Contains current hash value 
        /// </summary>
        public byte[] Hash { get; protected set; }

        /// <summary>
        /// Apply hash transform
        /// </summary>
        /// <param name="buffer">Bytes to hash</param>
        /// <returns>Hash value of the bytes from buffer</returns>
        public abstract void HashBytes(byte[] buffer);

        /// <summary>
        /// Apply hash transform
        /// </summary>
        /// <param name="stream">Input stream </param>
        /// <returns>Hash value of all bytes readed from the stream</returns>
        public virtual void HashBytes(Stream stream)
        {
            int bufSize = 4 * KBit;
            byte[] tempBuffer = new byte[bufSize];
            int readedBytes = 0;
            int appendIndex = 0;
            do
            {
                readedBytes = stream.Read(tempBuffer, readedBytes, bufSize - appendIndex);
                appendIndex += readedBytes;

                if (appendIndex == bufSize)
                {
                    HashBytes(tempBuffer, 0, bufSize);
                    appendIndex = 0;
                    readedBytes = 0;
                }
                else if (readedBytes == 0)
                {
                    HashFinal(tempBuffer, 0, appendIndex);
                }

            } while (readedBytes > 0);
        }

        /// <summary>
        /// Apply hash transform
        /// </summary>
        /// <param name="buffer">Bytes to hash</param>
        /// <param name="offset">Start position</param>
        /// <param name="length">Length of bytes to transform</param>
        public abstract void HashBytes(byte[] buffer, int offset, int length);

        public abstract void HashFinal();

        public abstract void HashFinal(byte[] buffer, int offset, int lenght);

        /// <summary>
        /// Reset state of the hash function to the initial value. 
        /// </summary>
        public abstract void ResetState();
    }
}
