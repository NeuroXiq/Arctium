using System;
using System.IO;
using Arctium.Shared.Exceptions;

namespace Arctium.Shared
{
    public class BufferForStream
    {
        public byte[] Buffer { get; private set; }
        public int DataLength { get; private set; }

        private Stream stream;

        public BufferForStream(Stream stream)
        {
            this.stream = stream;
            Buffer = new byte[GlobalConfig.DefaultBufferForStreamSize];
            DataLength = 0;
        }

        public void Write(byte[] buffer, int offset, int length)
        {
            stream.Write(buffer, offset, length);
        }

        public void LoadToLength(int minimumDataLengthInBuffer)
        {
            if (minimumDataLengthInBuffer <= DataLength) return;

            AppendMinimum(minimumDataLengthInBuffer - DataLength);
        }

        public void TrimStart(int bytesCountToRemoveFromStart)
        {
            if (bytesCountToRemoveFromStart > DataLength) throw new InvalidOperationException("Length of data in buffer is less that bytes to shift");

            for (int i = 0, j = bytesCountToRemoveFromStart; i < DataLength - bytesCountToRemoveFromStart; i++, j++)
            {
                Buffer[i] = Buffer[j];
            }

            DataLength -= bytesCountToRemoveFromStart;
        }

        public void AppendMinimum(int minimumToAppend)
        {
            if (minimumToAppend == 0)
            {
                return;
            }

            ExtendBufferIfNeeded(DataLength + minimumToAppend);

            int loaded = 0;
            int lastLoad = 0;
            int maxPossibleLoad = -1;

            do
            {
                maxPossibleLoad = Buffer.Length - DataLength;
                lastLoad = stream.Read(Buffer, DataLength, maxPossibleLoad);
                loaded += lastLoad;
                DataLength += lastLoad;

            } while (loaded < minimumToAppend && lastLoad > 0);

            if (loaded < minimumToAppend)
            {
                string msg = string.Format("Expected that stream return more bytes that it actually returns (loaded less bytes from stream than expected)");
                throw new ArctiumException(msg);
            }
        }

        private void ExtendBufferIfNeeded(int minimumBufferLength)
        {
            if (minimumBufferLength <= Buffer.Length)
            {
                return;
            }

            byte[] newBuffer = new byte[minimumBufferLength];
            MemCpy.Copy(Buffer, 0, newBuffer, 0, DataLength);

            Buffer = newBuffer;
        }

        public bool DataAvailable()
        {
            if (DataLength == 0)
            {
                int count = stream.Read(Buffer, 0, 1);
            }

            return true;
        }
    }
}
