using Arctium.Standards.Connection.Tls.Tls12.Configuration.TlsExtensions;
using Arctium.Standards.Connection.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Standards.Connection.Tls.Tls12.Configuration
{
    class Tls12ClientConfig
    {
        public CipherSuite[] EnableCipherSuites;
        public TlsHandshakeExtension[] Extensions;


        public object serverCertValidationCallback;
    }
}
