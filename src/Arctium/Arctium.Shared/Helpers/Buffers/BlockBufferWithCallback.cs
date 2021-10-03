using Arctium.Shared.Helpers.Buffers;
using System;
using System.IO;

namespace Arctium.Cryptography.HashFunctions.Hashes
{
    //COPY PASTE FROM hashes/hashhelpers
    // not sure to move
    public class BlockBufferWithCallback
    {
        public byte[] Buffer { get; private set; }

        public long DataLength { get; private set; }

        private readonly long blockSize;

        //invoked when Buffer is full.
        Action<byte[], long, long> limitReachedCallback;
        long bufferSize;

        public BlockBufferWithCallback(long bufferSize, long blockSize, Action<byte[], long, long> limitReachedCallback)
        {
            Buffer = new byte[bufferSize];
            this.bufferSize = bufferSize;
            this.limitReachedCallback = limitReachedCallback;
            DataLength = 0;
            this.blockSize = blockSize;
        }

        public void Reset()
        {
            DataLength = 0;
        }

        public long Load(byte[] buffer, long offset, long length)
        {
            long totalCopied = 0;

            //not exceeding ? just copy
            if ((DataLength + length) <= bufferSize)
            {
                MemCpy.Copy(buffer, offset, Buffer, DataLength, length);
                DataLength += length;

                totalCopied = length;

                if (DataLength == bufferSize)
                {
                    limitReachedCallback(Buffer, 0, DataLength);
                    DataLength = 0;
                }
                return totalCopied;
            }

            //exceeds, several cases

            //first,if some data is alerdy in buffer, copy to fill them and clear buffer ( DataLength = 0 )
            if (DataLength > 0)
            {
                MemCpy.Copy(buffer, offset, Buffer, DataLength, (bufferSize - DataLength));
                totalCopied += bufferSize - DataLength;
                limitReachedCallback(Buffer, 0, DataLength);
            }

            //maybe working with some large data,
            //now buffer is empty, for performance reasons invoke how many possible
            //callbacks directly on 'buffer' ignoring copy to 'Buffer'

            while ((length - totalCopied) >= bufferSize)
            {
                limitReachedCallback(buffer, offset + totalCopied, bufferSize);
                totalCopied += bufferSize;
            }

            //if some bytes left, append them to the buffer
            long remaining = length - totalCopied;
            MemCpy.Copy(buffer, (offset + totalCopied), Buffer, 0, (int)remaining);
            DataLength = remaining;

            return totalCopied;
        }

        public int Load(Stream inputStream)
        {
            int readLength = 0;
            int totalRead = 0;
            do
            {
                readLength = inputStream.Read(Buffer, (int)DataLength, (int)(bufferSize - DataLength));
                DataLength += readLength;
                totalRead += readLength;
                if (DataLength == bufferSize)
                {
                    limitReachedCallback(Buffer, 0, DataLength);
                    DataLength = 0;
                }
            } while (readLength > 0);

            return totalRead;
        }

        public long Flush(byte[] outBytesNotAlignedWithBlockLength, long outOffset, out long notAlignedBytesLength)
        {
            if (DataLength == 0)
            {
                notAlignedBytesLength = 0;

                return 0;    
            }

            long fullBlocksLengthInBytes = (DataLength / blockSize) * blockSize;
            long remainingBytes = DataLength - fullBlocksLengthInBytes;

            if (fullBlocksLengthInBytes > 0)
            {
                limitReachedCallback(Buffer, 0, fullBlocksLengthInBytes);
            }

            Array.Copy(Buffer, fullBlocksLengthInBytes, outBytesNotAlignedWithBlockLength, outOffset, remainingBytes);

            long dataLengthCpy = DataLength;
            DataLength = 0;

            notAlignedBytesLength = remainingBytes;

            return dataLengthCpy;
        }
    }
}
