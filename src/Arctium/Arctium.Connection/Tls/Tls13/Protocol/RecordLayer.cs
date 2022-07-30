using Arctium.Connection.Tls.Tls13.API;
using Arctium.Connection.Tls.Tls13.Model;
using Arctium.Shared.Helpers.Buffers;

namespace Arctium.Connection.Tls.Tls13.Protocol
{
    class RecordLayer
    {
        const int MaxRecordLength = 2 << 14;

        private BufferForStream bufferForStream;
        private byte[] buffer { get { return bufferForStream.Buffer; } }
        public byte[] RecordFragmentBytes { get; private set; }

        public RecordLayer(BufferForStream buffer)
        {
            this.bufferForStream = buffer;
            this.RecordFragmentBytes = new byte[MaxRecordLength];
        }

        public RecordInfo Read(bool isInitialClientHello = false)
        {
            int firstThreeFields = 5;
            ContentType contentType;
            ushort version;
            ushort length;

            bufferForStream.LoadToLength(firstThreeFields);

            byte contentTypeByte = (byte)buffer[0];
            version = (ushort)((buffer[1] << 8) | (buffer[2] << 0));
            length = (ushort)((buffer[3] << 8) | (buffer[4] << 0));

            Validate.RecordLayer.ValidateContentType(contentTypeByte);
            Validate.RecordLayer.ProtocolVersion(version, isInitialClientHello);
            Validate.RecordLayer.Length(length);

            contentType = (ContentType)contentTypeByte;

            bufferForStream.LoadToLength(firstThreeFields + length);

            MemCpy.Copy(buffer, firstThreeFields, RecordFragmentBytes, 0, length);

            return new RecordInfo(contentType, version, length);
        }

        public void Write()
        {
        }

        

        public struct RecordInfo
        {
            public ContentType ContentType;
            ushort ProtocolVersion;
            public int Length;

            public RecordInfo(ContentType contentType, ushort protocolVersion, int length)
            {
                ContentType = contentType;
                ProtocolVersion = protocolVersion;
                Length = length;
            }
        }
    }
}
