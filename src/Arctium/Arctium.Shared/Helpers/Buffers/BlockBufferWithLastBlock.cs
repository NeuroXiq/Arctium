using System;
using System.Collections.Generic;
using System.Text;
using System.IO;

namespace Arctium.Shared.Helpers.Buffers
{
    public class BlockBufferWithLastBlock
    {
        private byte[] buffer;
        private long blockSize;
        private long dataCountInLastBlock;
        private byte[] streamBuffer;

        public delegate void Callback(byte[] buffer, long offset, long length);
        private Callback callback;

        public BlockBufferWithLastBlock(long blockLength, long bufferSizeInBlocks, Callback callback)
        {
            if (blockLength < 1) throw new ArgumentException(nameof(blockLength));
            if (bufferSizeInBlocks < 1) throw new ArgumentException(nameof(bufferSizeInBlocks));

            this.callback = callback;
            buffer = new byte[blockLength * (bufferSizeInBlocks + 1)];
            blockSize = bufferSizeInBlocks;
            streamBuffer = null;
        }

        public void Load(byte[] buffer, long offset, long length)
        {
        
        }

        public void Load(byte[] buffer)
        {
            this.Load(buffer, 0, buffer.Length);
        }

        public void Load(Stream stream)
        {
            if (streamBuffer == null) streamBuffer = new byte[buffer.Length];

            int lastReadCount = -1;
            int totalRead = 0;

            do
            {
                lastReadCount = stream.Read(streamBuffer, 0, buffer.Length);

            }
            while (lastReadCount > 0);
            

                
            
        }
    }
}
