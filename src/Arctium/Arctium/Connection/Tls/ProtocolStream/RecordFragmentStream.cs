using Arctium.Connection.Tls.Protocol.RecordProtocol;
using System;
using System.Collections.Generic;

namespace Arctium.Connection.Tls.ProtocolStream
{
    ///<summary>Contains decrypted,  decompressed fragments with associated <see cref="ContentType"/></summary>
    class RecordFragmentStream
    {

        public bool CanRead { get { return fragmentsQueueStream.Count > 0; } }

        class ContentFragmentData
        {
            public byte[] Bytes;
            public ContentType Type;
            public int PositionToRead;

            public ContentFragmentData(byte[] bytes, ContentType type)
            {
                Bytes = bytes;
                Type = type;
                PositionToRead = 0;
            }
        }

        Queue<ContentFragmentData> fragmentsQueueStream;

        public RecordFragmentStream()
        {
            fragmentsQueueStream = new Queue<ContentFragmentData>();
        }

        public int ReadFragment(byte[] buffer, int offset, int count, out ContentType contentType)
        {
            if (fragmentsQueueStream.Count == 0) throw new InvalidOperationException("Cannot read fragment from empty stream");
            int toRead = CalculateToReadLength(count);
            ContentFragmentData data = fragmentsQueueStream.Peek();

            for (int i = 0; i < toRead; i++)
            {
                buffer[i + offset] = data.Bytes[i + data.PositionToRead];
            }

            data.PositionToRead += toRead;

            contentType = data.Type;

            if (data.PositionToRead == data.Bytes.Length) fragmentsQueueStream.Dequeue();

            return toRead;
        }

        private int CalculateToReadLength(int count)
        {
            ContentFragmentData data = fragmentsQueueStream.Peek();

            int maxToRead = data.Bytes.Length - data.PositionToRead;

            if (maxToRead >= count) return count;
            else return maxToRead;
        }

        public void AppendFragment(byte[] buffer, int offset, int length, ContentType contentType)
        {
            byte[] temporary = new byte[length];
            for (int i = 0; i < length; i++)
            {
                temporary[i] = buffer[offset + i];
            }

            ContentFragmentData data = new ContentFragmentData(temporary, contentType);

            fragmentsQueueStream.Enqueue(data);

        }
    }
}
