using Arctium.Connection.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Formatter.HandshakeFormatters
{
    abstract class HandshakeFormatterBase
    {
        public abstract int GetLength(Handshake handshake);
        public abstract int GetBytes(byte[] buffer, int offset, Handshake handshakeMessage);
    }
}
