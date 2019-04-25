using Arctium.Connection.Tls.Protocol.RecordProtocol;
using System;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Builder
{
    class RecordBuilder
    {

        public RecordBuilder()
        {

        }

        public Record GetRecord(byte[] buffer, int offset)
        {
            

            ContentType contentType = GetContentType(buffer, offset);
            ProtocolVersion version = GetVersion(buffer, offset);
            ushort length = NumberConverter.ToUInt16(buffer, offset + ProtocolFormatConst.RecordLengthOffset);

            int expectedLength = length + ProtocolFormatConst.RecordHeaderLength;

            byte[] fragment = GetFragment(buffer, offset, length);

            Record record = new Record();
            record.Length = length;
            record.Version = version;
            record.Type = contentType;
            record.Fragment = fragment;

            return record;
        }

        private byte[] GetFragment(byte[] buffer, int offset, ushort fragmentLength)
        {
            int fragmentStartOffset = offset + ProtocolFormatConst.RecordFragmentOffset;

            byte[] fragmentBuff = new byte[fragmentLength];
            for (int i = 0; i < fragmentLength; i++)
            {
                fragmentBuff[i] = buffer[fragmentStartOffset + i];
            }

            return fragmentBuff;
        }

        private ushort GetLength(byte[] buffer, int recordOffset)
        {
            int lenOff = ProtocolFormatConst.RecordLengthOffset;

            //explicit conversion as big-endian
            ushort length =(ushort)
                           ((buffer[recordOffset + lenOff + 1] << 8) |
                           ( buffer[recordOffset + lenOff + 0] << 0));

            return length;
        }

        private ContentType GetContentType(byte[] buffer, int recordOffset)
        {
            int ctOffset = ProtocolFormatConst.RecordContentTypeOffset;
            byte contentTypeByte = buffer[recordOffset + ctOffset];

            if (!Enum.IsDefined(typeof(ContentType), contentTypeByte))
            {
                string msg = "Cannot parse 'ContentType' value of current record. Any 'ContentType' is not associated with value founded in record";
                throw new RecordParserException(msg);
            }

            return (ContentType)contentTypeByte;
        }

        private ProtocolVersion GetVersion(byte[] buffer, int recordOffset)
        {
            int verOffset = ProtocolFormatConst.RecordProtocolVersionOffset;

            byte major = buffer[recordOffset + verOffset];
            byte minor = buffer[recordOffset + verOffset + 1];

            return new ProtocolVersion(major, minor);
        }
    }
}
