using Arctium.Protocol.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Protocol.Tls.Protocol.BinaryOps.Formatter.HandshakeFormatters
{
    abstract class HandshakeFormatterBase
    {
        public abstract int GetLength(Handshake handshake);
        public abstract int GetBytes(byte[] buffer, int offset, Handshake handshakeMessage);
    }
}
