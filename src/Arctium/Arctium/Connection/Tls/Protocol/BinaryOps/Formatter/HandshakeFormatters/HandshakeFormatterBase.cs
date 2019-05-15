using Arctium.Connection.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Formatter.HandshakeFormatters
{
    abstract class HandshakeFormatterBase
    {
        public abstract int GetLength(Handshake handshake);
        public abstract void FormatBytes(Handshake hs, byte[] buffer, int offset);
    }
}
