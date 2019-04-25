using Arctium.Connection.Tls.Protocol.FormatConsts;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.FixedOps
{
    class FixedHandshakeInfo
    {
        ///<summary>Offset of first byte of handshake struct</summary>
        public static int Length(byte[] buffer, int offset)
        {
            return (int)NumberConverter.ToUInt24(buffer, offset + HandshakeConst.LengthOffset);
        }
    }
}
