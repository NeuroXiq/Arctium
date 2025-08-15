using Arctium.Shared;
using System;
using System.IO;

namespace Arctium.Cryptography.HashFunctions.XOF
{
    // Class assumes, that lots of underlying function will be a some 
    // algorithms that takes input as fixed-length blocks of data.
    // If not, need to override methods to behave like this 

    /// <summary>
    /// Base class for all XOF function algorithms
    /// </summary>
    public abstract class XOFBase
    {
        /// <summary>
        /// Bit length of the output block of underlying function.
        /// </summary>
        public int OutputBlockLength { get; set; }

        //assume that underlying function are hash function with some fixed-input block length.
        //then for optimization 

        /// <summary>
        /// Expected input block length in bytes
        /// </summary>
        protected int inputBlockLength;

        //all loaded bytes (processed by feed + in callback buffer not processed yet)
        protected long FeedBytesCount { get; set; }

        protected BlockBufferWithCallback bufferWithCallback;


        protected XOFBase(int outputBlockLength, int inputBlockBitLength)
        {
            OutputBlockLength = outputBlockLength;
            this.inputBlockLength = inputBlockBitLength / 8;
            if (inputBlockBitLength <= 0)
            {
                inputBlockLength = XOFConfiguration.XOFBase.DefaultInputBlockSize;
            }
            else this.inputBlockLength = inputBlockBitLength / 8;

            bufferWithCallback = new BlockBufferWithCallback(
                inputBlockBitLength * XOFConfiguration.XOFBase.CallbackBufferBlockCount,
                inputBlockBitLength / 8,
                new Action<byte[],long,long>(Feed));;

            FeedBytesCount = 0;
        }

        public virtual long Feed(byte[] buffer)
        {
            long result = bufferWithCallback.Load(buffer,0,buffer.Length);
            FeedBytesCount += result;

            return result;
        }

        public virtual long Feed(Stream stream)
        {
            long result = bufferWithCallback.Load(stream);
            FeedBytesCount += result;
            return result;
        }

        public virtual void FeedEnd()
        {
            byte[] padding = GetPadding();
            bufferWithCallback.Load(padding, 0, padding.Length);

            // after loadng data, callback was invoked ? 
            if (bufferWithCallback.DataLength > 0)
            {
                //nope, feed what not yet been feeded by buffer
                Feed(bufferWithCallback.Buffer, 0, bufferWithCallback.DataLength);
            }

            bufferWithCallback.Reset();
        }

        public virtual void Reset()
        {
            this.FeedBytesCount = 0;
            this.bufferWithCallback.Reset();
            ResetState();
        }

        public virtual void GenerateNextOutput(byte[] outputBuffer, long offset, long blockCount)
        {
            for (long i = offset; i < offset + (blockCount * (OutputBlockLength/8)); i+=OutputBlockLength)
            {
                GenerateNextOutputBytes(outputBuffer, i);
            }
        }

        public abstract void GenerateNextOutputBytes(byte[] buffer, long offset);

        protected abstract void ResetState();

        protected abstract void Feed(byte[] buffer, long offset, long length);

        /// <summary>
        /// if underlying function input is a fixed-size blocks, assumes that lots of function will override this method.
        /// </summary>
        /// <returns></returns>
        protected abstract byte[] GetPadding();
    }
}
