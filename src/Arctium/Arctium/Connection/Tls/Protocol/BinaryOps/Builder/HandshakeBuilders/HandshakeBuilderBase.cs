using Arctium.Connection.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Builder.HandshakeBuilders
{
    abstract class HandshakeBuilderBase
    {
        ///<summary></summary>
        ///<param name="offset">Offsets indiactes handshake message offset (first byte after handshake_type and length)</param>
        ///<param name="length">Length of message in bytes</param>
        public abstract Handshake BuildFromBytes(byte[] buffer, int offset, int length);
        


    }
}
