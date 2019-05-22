using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions;

namespace Arctium.Connection.Tls.Configuration.TlsExtensions
{
    //
    // Hides internal representation of the handshake extensions to public usage
    //

    public class TlsHandshakeExtension
    {
        HandshakeExtensionType internalExtensionType;

        protected TlsHandshakeExtension(HandshakeExtensionType type)
        {
            internalExtensionType = type;
        }
    }
}
