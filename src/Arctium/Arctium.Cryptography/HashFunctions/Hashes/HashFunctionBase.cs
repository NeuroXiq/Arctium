using Arctium.Cryptography.HashFunctions.Hashes.Configuration;
using Arctium.Shared.Helpers.Buffers;
using System;
using System.IO;

namespace  Arctium.Cryptography.HashFunctions.Hashes
{
    /// <summary>
    /// Base class for all hash function.
    /// </summary>
    public unsafe abstract class HashFunctionBase
    {
        /// <summary>
        /// Input block size in bits
        /// </summary>
        public int InputBlockSize { get; private set; }

        /// <summary>
        /// Output hash size in bits.
        /// </summary>
        public int HashSize { get; private set; }

        protected BlockBufferWithUnsafeCallback dataBufferWithCallback;

        protected bool hashFinalCalled;

        /// <summary>
        /// Count of all processed blocks, include blocks with padding.
        /// </summary>

        // protected ulong HashedBlocksCount { get; set; }

        /// <summary>
        /// Length of all bytes loaded to the hash function from buffer or stream. 
        /// This length include both: already hashed bytes of the message and not hashed yet but loaded into internal buffer.
        /// This length do not include padding applied in HashFinal()
        /// </summary>
        protected long CurrentMessageLengthWithoutPadding { get; set; }

        protected HashFunctionBase(int inputBlockSize, int hashSize)
        {
            InputBlockSize = inputBlockSize;
            HashSize = hashSize;

            int blockSizeInBytes = inputBlockSize / 8;
            int bufferSize = HashFunctionsConfig.BufferSizeInBlocks * (inputBlockSize / 8);
            dataBufferWithCallback = new BlockBufferWithUnsafeCallback(bufferSize, blockSizeInBytes, new BlockBufferWithUnsafeCallback.Callback(this.HashDataBufferCallback));

            hashFinalCalled = false;
        }

        /// <summary>
        /// Apply hash transform
        /// </summary>
        /// <param name="buffer">Bytes to hash</param>
        /// <returns>Hash value of the bytes from buffer</returns>
        public virtual long HashBytes(byte[] buffer)
        {
            long loaded = dataBufferWithCallback.Load(buffer, 0, buffer.Length);
            CurrentMessageLengthWithoutPadding += loaded;

            return loaded;
        }

        /// <summary>
        /// Apply hash transform
        /// </summary>
        /// <param name="stream">Input stream </param>
        /// <returns>Hash value of all bytes readed from the stream</returns>
        public virtual long HashBytes(Stream stream)
        {
            long loaded = dataBufferWithCallback.Load(stream);
            CurrentMessageLengthWithoutPadding += loaded;
            return loaded;
        }

        /// <summary>
        /// Apply hash transform
        /// </summary>
        /// <param name="buffer">Bytes to hash</param>
        /// <param name="offset">Start position</param>
        /// <param name="length">Length of bytes to transform</param>
        public virtual long HashBytes(byte[] buffer, long offset, long length)
        {
            long loaded = dataBufferWithCallback.Load(buffer, offset, length);
            CurrentMessageLengthWithoutPadding += loaded;

            return loaded;
        }

        public virtual byte[] HashFinal()
        {
            if (hashFinalCalled) throw new InvalidOperationException("HashFinal can be called only once after ResetState or instance creation.");
            hashFinalCalled = true;

            byte[] padding = GetPadding();

            if (padding != null) { dataBufferWithCallback.Load(padding, 0, padding.Length); }
            

            // hashDataBuffer may call hashing method because after padding append,
            // buffer is filled exactly to end (exact multiply of hash input block) and callback was invoked,
            // right after Load() call
            if(dataBufferWithCallback.Count > 0)
                dataBufferWithCallback.FlushBuffer();


            return GetCurrentHash();
        }

        private void HashDataBufferCallback(byte* buffer, long length)
        {
            ExecuteHashing(buffer, length);
        }

        protected abstract byte[] GetPadding();

        //this function is a main function implemented by all hash functions. This is where specific hashing for specific hash function shall be executed.
        //'length' must be multiply of the input block size.
        protected abstract void ExecuteHashing(byte* buffer, long length);

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
            // HashedBlocksCount = 0;
            CurrentMessageLengthWithoutPadding = 0;
            dataBufferWithCallback.Clear();
        }
    }
}
