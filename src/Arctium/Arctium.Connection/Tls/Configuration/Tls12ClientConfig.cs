using Arctium.Connection.Tls.Configuration.TlsExtensions;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Connection.Tls.Configuration
{
    class Tls12ClientConfig
    {
        public CipherSuite[] EnableCipherSuites;
        public TlsHandshakeExtension[] Extensions;


        public object serverCertValidationCallback;
    }
}
