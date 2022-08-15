using Arctium.Connection.Tls.Tls13.API;
using Arctium.Connection.Tls.Tls13.Model;
using Arctium.Shared.Helpers.Buffers;

namespace Arctium.Connection.Tls.Tls13.Protocol
{
    class RecordLayer
    {
        const int MaxRecordLength = 2 << 14;
        const int WriteBufferLength = MaxRecordLength + 1 + 2 + 2;
        const byte LegacyVersion = 0x03;

        private BufferForStream bufferForStream;
        private Validate validate;

        private byte[] buffer { get { return bufferForStream.Buffer; } }
        public byte[] RecordFragmentBytes { get; private set; }
        private byte[] writeBuffer;

        public RecordLayer(BufferForStream buffer, Validate validate)
        {
            this.bufferForStream = buffer;
            this.validate = validate;
            this.RecordFragmentBytes = new byte[MaxRecordLength];
            this.writeBuffer = new byte[WriteBufferLength];
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

            validate.RecordLayer.ValidateContentType(contentTypeByte);
            validate.RecordLayer.ProtocolVersion(version, isInitialClientHello);
            validate.RecordLayer.Length(length);

            contentType = (ContentType)contentTypeByte;

            bufferForStream.LoadToLength(firstThreeFields + length);

            MemCpy.Copy(buffer, firstThreeFields, RecordFragmentBytes, 0, length);

            return new RecordInfo(contentType, version, length);
        }

        public void Write(ContentType contentType, byte[] buffer, long offset, long length)
        {
            int chunkLen = MaxRecordLength;
            int chunks = (int)(length + chunkLen - 1) / chunkLen;

            for (int i = 0; i < chunks; i++)
            {
                long start = (i * chunkLen) + offset;
                ushort len = (ushort)(length - (i * chunkLen) + 1);

                WriteRecord(contentType, buffer, start, len);
            }
        }

        void WriteRecord(ContentType type, byte[] buffer, long offset, ushort length)
        {
            writeBuffer[0] = (byte)type;
            writeBuffer[1] = writeBuffer[2] = LegacyVersion;
            MemMap.ToBytes1UShortBE(length, writeBuffer, 3);

            int bytesLen = 5 + length;

            bufferForStream.Write(writeBuffer, 0, bytesLen);
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
