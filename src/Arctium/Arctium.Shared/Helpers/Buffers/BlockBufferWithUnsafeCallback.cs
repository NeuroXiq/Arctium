using System;
using System.IO;

namespace Arctium.Shared.Helpers.Buffers
{
    public unsafe class BlockBufferWithUnsafeCallback
    {
        public readonly int BlockSize;
        public readonly int BufferSize;

        public long Count { get { return bytesInBuffer; } }
        public byte[] Buffer { get { return buffer; } }

        public delegate void Callback(byte* buffer, long bytesCount);

        byte[] buffer;
        long bytesInBuffer;

        Callback callback;

        public BlockBufferWithUnsafeCallback(int bufferSize, int blockSize, Callback callback)
        {
            buffer = new byte[bufferSize];
            BufferSize = bufferSize;
            BlockSize = blockSize;
            this.callback = callback;
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

                // execute callback directly on input buffer instead of copy to inner buffer and then callback
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
