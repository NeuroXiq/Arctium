using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Formatter.HandshakeFormatters.ExtensionsFormatters
{
    abstract class ExtensionFormatterBase
    {
        public abstract int GetLength(HandshakeExtension extension);
        public abstract int GetBytes(byte[] buffer, int offset, HandshakeExtension extension);
    }
}
