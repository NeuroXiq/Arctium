using System;
using Arctium.Connection.Tls.Protocol;
using Arctium.Connection.Tls.RecordProtocol;

namespace Arctium.Connection.Tls.BinaryOps.Parser
{
    class RecordParser
    {

        public RecordParser()
        {

        }

        public Record GetRecord(byte[] buffer, int offset, int count)
        {
            if (count < ProtocolFromatConst.RecordHeaderLength) throw new RecordParserException("Invalid Record fromat. Bytes length do not reach minimum value");

            ContentType contentType = GetContentType(buffer, offset);
            ProtocolVersion version = GetVersion(buffer, offset);
            ushort length = GetLength(buffer, offset);

            int expectedLength = length + ProtocolFromatConst.RecordHeaderLength;
            int currentLength = count;

            if (currentLength != expectedLength)
                throw new RecordParserException("Invalid length of record." +
                 " Expected length of entire record in bytes differs from length provided in 'count' param");

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
            int fragmentStartOffset = offset + ProtocolFromatConst.RecordFragmentOffset;

            byte[] fragmentBuff = new byte[fragmentLength];
            for (int i = 0; i < fragmentLength; i++)
            {
                fragmentBuff[i] = buffer[fragmentStartOffset + i];
            }

            return fragmentBuff;
        }

        private ushort GetLength(byte[] buffer, int recordOffset)
        {
            int lenOff = ProtocolFromatConst.RecordLengthOffset;

            //explicit conversion as big-endian
            ushort length =(ushort)
                           ((buffer[recordOffset + lenOff + 1] << 8) |
                           ( buffer[recordOffset + lenOff + 0] << 0));

            return length;
        }

        private ContentType GetContentType(byte[] buffer, int recordOffset)
        {
            int ctOffset = ProtocolFromatConst.RecordContentTypeOffset;
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
            int verOffset = ProtocolFromatConst.RecordProtocolVersionOffset;

            byte major = buffer[recordOffset + verOffset];
            byte minor = buffer[recordOffset + verOffset + 1];

            return new ProtocolVersion(major, minor);
        }
    }
}
