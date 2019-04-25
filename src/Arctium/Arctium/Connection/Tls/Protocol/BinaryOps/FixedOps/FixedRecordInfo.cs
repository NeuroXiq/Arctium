using Arctium.Connection.Tls.Protocol.FormatConsts;
using Arctium.Connection.Tls.Protocol.RecordProtocol;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.FixedOps
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
    }
}
