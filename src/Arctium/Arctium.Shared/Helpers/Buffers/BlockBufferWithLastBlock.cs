using System;
using System.Collections.Generic;
using System.Text;
using System.IO;

namespace Arctium.Shared.Helpers.Buffers
{
    public class BlockBufferWithLastBlock
    {
        public delegate void Callback(byte[] buffer, long offset, long length);

        private long blockSize;
        private long loadedInBuffer;
        private long bufferSize;
        private byte[] byteBuffer;
        private byte[] streamBuffer;
        private Callback callback;

        public BlockBufferWithLastBlock(long blockLength, long bufferSizeInBlocks, Callback callback)
        {
            if (blockLength < 1) throw new ArgumentException(nameof(blockLength));
            if (bufferSizeInBlocks < 1) throw new ArgumentException(nameof(bufferSizeInBlocks));

            this.callback = callback;
            byteBuffer = new byte[blockLength * (bufferSizeInBlocks + 1)];
            blockSize = blockLength;
            streamBuffer = null;
            bufferSize = blockLength * bufferSizeInBlocks;
        }

        public void Load(byte[] buffer, long offset, long length)
        {
            if (length == 0) return;

            long maxLoad = (byteBuffer.Length - loadedInBuffer);
            long toLoad = length > maxLoad ? maxLoad : length;
            long remaining = length;
            long loadOffset = offset;
            
            for(long i = 0; i < toLoad; i++) byteBuffer[i + loadedInBuffer] = buffer[i + offset];
            loadedInBuffer += toLoad;
            remaining -= toLoad;
            loadOffset += toLoad;

            if (remaining == 0) 
            {
                if (loadedInBuffer == byteBuffer.Length) Flush();
                return;
            } 

            this.callback(byteBuffer, 0, byteBuffer.Length);
            loadedInBuffer = 0;

            if (remaining > buffer.Length)
            {
                long lastBlockOffset = (length / blockSize) * blockSize;
                lastBlockOffset = length % blockSize == 0 ? lastBlockOffset - 1 : lastBlockOffset;
                long lastBlockLength = length - (lastBlockOffset * blockSize) + 1;
                long bytesCountFullBlocks = remaining - lastBlockLength;

                this.callback(buffer, loadOffset, bytesCountFullBlocks);

                loadOffset += bytesCountFullBlocks;
                remaining = lastBlockLength;
            }

            for(long i = 0; i < remaining; i++) byteBuffer[i] = buffer[i + loadOffset];
            loadedInBuffer = remaining;

            if (loadedInBuffer == buffer.Length) Flush();
        }

        ///<summary>
        /// Flush data from the buffer. Flush operation never flush last block. If only last block is present
        /// in the buffer, then nothing is flushed. To get last block from buffer use 
        ///</summary>
        public void Flush()
        {
            long toFlushWithoutLastBlock = ((loadedInBuffer + blockSize - 1) / blockSize) - 1;
            long bytesCount = toFlushWithoutLastBlock * blockSize;
            
            if (toFlushWithoutLastBlock < 1) return;

            this.callback(byteBuffer, 0, bytesCount);
            loadedInBuffer -= bytesCount;
            MemCpy.Copy(byteBuffer, bytesCount, byteBuffer, 0, loadedInBuffer);
        }

        public void Load(byte[] buffer)
        {
            this.Load(buffer, 0, buffer.Length);
        }

        public long Load(Stream stream)
        {
            if (streamBuffer == null) streamBuffer = new byte[byteBuffer.Length];

            int lastReadCount = -1;
            int totalRead = 0;

            lastReadCount = stream.Read(streamBuffer, 0, streamBuffer.Length);
            
            while (lastReadCount > 0)
            {
                totalRead += lastReadCount;
                Load(streamBuffer, 0, lastReadCount);
                lastReadCount = stream.Read(streamBuffer, 0, streamBuffer.Length);
            }

            return totalRead;
        }

        public long FlushWithLastBlock(byte[] buffer, long offset)
        {
            long lastBlockLength;

            Flush();

            MemCpy.Copy(byteBuffer, 0, buffer, offset, loadedInBuffer);

            lastBlockLength = loadedInBuffer;
            loadedInBuffer = 0;

            return lastBlockLength;
        }
    }
}
