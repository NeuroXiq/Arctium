using Arctium.Connection.Tls.Tls12.Configuration.TlsExtensions;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Connection.Tls.Tls12.Configuration
{
    class Tls12ClientConfig
    {
        public CipherSuite[] EnableCipherSuites;
        public TlsHandshakeExtension[] Extensions;


        public object serverCertValidationCallback;
    }
}
