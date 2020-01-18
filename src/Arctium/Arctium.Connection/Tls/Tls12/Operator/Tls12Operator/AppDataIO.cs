using Arctium.Connection.Tls.Protocol.RecordProtocol;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12;
using System;

namespace Arctium.Connection.Tls.Tls12.Operator.Tls12Operator
{
    ///<summary>Reading application data in stream manner. Readed content type can also be determined before read</summary>
    class AppDataIO
    {
        byte[] fragmentBuffer = new byte[0x4800];
        RecordLayer12 recordLayer;

        public ContentType CurrentContentType { get; private set; }

        int readOffset;
        int dataLength;

        public AppDataIO(RecordLayer12 recordLayer)
        {
            this.recordLayer = recordLayer;
            readOffset = 0;
        }

        public void PrepareToRead()
        {
            if (dataLength > 0) return;

            ContentType type;
            dataLength = recordLayer.ReadFragment(fragmentBuffer, 0, out type);

            CurrentContentType = type;
            readOffset = 0;
        }

        public void Write(byte[] buffer, int offset, int length)
        {
            recordLayer.Write(buffer, offset, length, ContentType.ApplicationData);
        }

        public int Read(byte[] buffer, int offset, int count)
        {
            int copyCount = count <= dataLength ? count : dataLength;

            Buffer.BlockCopy(fragmentBuffer, readOffset, buffer, offset, copyCount);
            readOffset += copyCount;
            dataLength -= copyCount;

            return copyCount;
        }
    }
}
