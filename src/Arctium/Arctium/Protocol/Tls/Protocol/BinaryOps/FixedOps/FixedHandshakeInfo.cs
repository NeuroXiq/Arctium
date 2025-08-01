using Arctium.Protocol.Tls.Protocol.Consts;

namespace Arctium.Protocol.Tls.Protocol.BinaryOps.FixedOps
{
    class FixedHandshakeInfo
    {
        ///<summary>Offset of the first byte o thef handshake struct</summary>
        public static int Length(byte[] buffer, int offset)
        {
            return (int)NumberConverter.ToUInt24(buffer, offset + HandshakeConst.LengthOffset);
        }
    }
}
