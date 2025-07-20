using System;
using System.IO;

namespace Arctium.Shared.Helpers.Buffers
{
    /// <summary>
    /// If amount of data reach buffer size then specified callback is invoked
    /// </summary>
    public unsafe class ByteBufferWithUnsafeCallback
    {
        public readonly int BufferSize;

        public long Count { get { return bytesInBuffer; } }
        public byte[] Buffer { get { return buffer; } }
        
        /// <summary>
        /// Indicates if buffer contains any data
        /// </summary>
        public bool HasData { get { return Count > 0; } }

        public delegate void Callback(byte* buffer, long bytesCount);

        byte[] buffer;
        long bytesInBuffer;

        Callback callback;

        public ByteBufferWithUnsafeCallback(int bufferSize, Callback callback)
        {
            buffer = new byte[bufferSize];
            BufferSize = bufferSize;
            this.callback = callback;
        }

        public long Load(byte[] input)
        {
            return Load(input, 0, input.Length);
        }

        public long Load(byte[] input, long offset, long length)
        {
            long loaded = LoadMaxPossibleDataToBuffer(input, offset, length);
            long remainingToLoad = length - loaded;

            if (bytesInBuffer == buffer.Length)
            {
                FlushBuffer();
            }

            if (remainingToLoad < buffer.Length)
            {
                LoadMaxPossibleDataToBuffer(input, offset + loaded, remainingToLoad);
            }
            else
            {
                long blocksCount = remainingToLoad / buffer.Length;
                long remainigAfterBlocks = remainingToLoad % buffer.Length;
                long remainingOffset = (blocksCount * buffer.Length) + loaded;

                // execute callback directly on input buffer instead of copy to inner buffer
                fixed (byte* inputPtr = &input[loaded])
                {
                    callback(inputPtr, blocksCount * buffer.Length);
                }

                LoadMaxPossibleDataToBuffer(input, remainingOffset, remainigAfterBlocks);
            }

            return length;
        }

        public long Load(Stream stream)
        {
            long curRead = 0;
            long totalRead = 0;

            do
            {
                curRead = stream.Read(buffer, (int)bytesInBuffer, (int)(buffer.Length - bytesInBuffer));
                totalRead += curRead;
                bytesInBuffer += curRead;

                if (buffer.Length == bytesInBuffer)
                    FlushBuffer();
            }
            while (curRead > 0);

            return totalRead;
        }

        public void FlushBuffer()
        {
            fixed (byte* bufferPtr = &buffer[0])
            {
                callback(bufferPtr, bytesInBuffer);
            }

            bytesInBuffer = 0;
        }

        public void Clear()
        {
            bytesInBuffer = 0;
        }

        private long LoadMaxPossibleDataToBuffer(byte[] input, long offset, long length)
        {
            long maxPossibleLoad = bytesInBuffer + length > buffer.Length ?
                buffer.Length - bytesInBuffer : length;

            Array.Copy(input, (int)offset, buffer, bytesInBuffer, maxPossibleLoad);
            bytesInBuffer += maxPossibleLoad;

            return maxPossibleLoad;
        }
    }
}
