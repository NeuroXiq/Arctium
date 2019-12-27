using Arctium.Cryptography.HashFunctions.Configuration;
using Arctium.DllGlobalShared.Optimalization;
using System;
using System.IO;

namespace Arctium.Cryptography.HashFunctions
{
    /// <summary>
    /// Base class for all hash function.
    /// </summary>
    public abstract class HashFunctionBase
    {
        /// <summary>
        /// Input block size in bits
        /// </summary>
        public int InputBlockSize { get; private set; }

        /// <summary>
        /// Output hash size in bits.
        /// </summary>
        public int HashSize { get; private set; }

        private protected HashDataBuffer hashDataBuffer;

        private bool hashFinalCalled;
        protected long hashedBytesCount;

        protected HashFunctionBase(int inputBlockSize, int hashSize)
        {
            InputBlockSize = inputBlockSize;
            HashSize = hashSize;

            int bufferSize = HashFunctionsConfig.Common_HashDataBuffer_BufferSize * (inputBlockSize / 8);

            hashDataBuffer = new HashDataBuffer(bufferSize, (buffer, offset, length) => HashDataBufferCallback(buffer, offset, length));
            hashFinalCalled = false;
        }

        /// <summary>
        /// Apply hash transform
        /// </summary>
        /// <param name="buffer">Bytes to hash</param>
        /// <returns>Hash value of the bytes from buffer</returns>
        public virtual int HashBytes(byte[] buffer)
        {
            return hashDataBuffer.Load(buffer, 0, buffer.Length);
        }

        /// <summary>
        /// Apply hash transform
        /// </summary>
        /// <param name="stream">Input stream </param>
        /// <returns>Hash value of all bytes readed from the stream</returns>
        public virtual int HashBytes(Stream stream)
        {
            return hashDataBuffer.Load(stream);
        }

        /// <summary>
        /// Apply hash transform
        /// </summary>
        /// <param name="buffer">Bytes to hash</param>
        /// <param name="offset">Start position</param>
        /// <param name="length">Length of bytes to transform</param>
        public virtual int HashBytes(byte[] buffer, int offset, int length)
        {
            return hashDataBuffer.Load(buffer, offset, length);
        }

        public virtual byte[] HashFinal()
        {
            if (hashFinalCalled) throw new InvalidOperationException("HashFinal can be called only once after ResetState or instance creation.");
            hashFinalCalled = true;

            byte[] padding = GetPadding();
            hashDataBuffer.Load(padding,0,padding.Length);
            
            //hashDataBuffer may call hashing method because after padding append, buffer is filled and callback was invoked.
            if(hashDataBuffer.DataLength > 0)
                ExecuteHashing(hashDataBuffer.Buffer, 0, hashDataBuffer.DataLength);

            return GetCurrentHash();
        }

        private void HashDataBufferCallback(byte[] buffer, int offset, int length)
        {
            ExecuteHashing(buffer, offset, length);
            hashedBytesCount += length;
        }

        protected abstract byte[] GetPadding();

        //this function is a main function implemented by all hash functions. This is where specific hashing for specific hash function shall be executed.
        //'length' must be multiply of the input block size.
        protected abstract void ExecuteHashing(byte[] buffer, int offset, int length);

        /// <summary>
        /// Returns current hash state.
        /// </summary>
        /// <returns></returns>
        protected abstract byte[] GetCurrentHash();

        /// <summary>
        /// Reset state of the hash function to the initial value. 
        /// </summary>
        public virtual void ResetState()
        {
            hashFinalCalled = false;
            hashedBytesCount = 0;
            hashDataBuffer.Clear();
        }
    }
}
