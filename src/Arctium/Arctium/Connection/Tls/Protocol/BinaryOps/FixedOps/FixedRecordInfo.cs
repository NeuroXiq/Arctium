using Arctium.Standards.Connection.Tls.Protocol.Consts;
using Arctium.Standards.Connection.Tls.Protocol.RecordProtocol;

namespace Arctium.Standards.Connection.Tls.Protocol.BinaryOps.FixedOps
{
    static class FixedRecordInfo
    {
        ///<summary></summary>
        ///<param name="offset">record start offset</param>
        public static ushort FragmentLength(byte[] buffer, int offset)
        {
            return NumberConverter.ToUInt16(buffer, offset + RecordConst.LengthOffset);
        }

        public static ContentType GetContentType(byte[] buffer, int offset)
        {
            return (ContentType)buffer[offset];
        }

        public static RecordHeader GetHeader(byte[] buffer, int recordOffset)
        {
            ContentType contentType = (ContentType)buffer[recordOffset];
            ProtocolVersion version = new ProtocolVersion(buffer[recordOffset + 1], buffer[recordOffset + 2]);
            int length = NumberConverter.ToUInt16(buffer, recordOffset + RecordConst.LengthOffset);

            RecordHeader header = new RecordHeader(contentType, version, length);

            return header;
        }
    }
}
