using Arctium.Protocol.Tls.Tls12.Configuration.TlsExtensions;
using Arctium.Protocol.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Protocol.Tls.Tls12.Configuration
{
    class Tls12ClientConfig
    {
        public CipherSuite[] EnableCipherSuites;
        public TlsHandshakeExtension[] Extensions;


        public object serverCertValidationCallback;
    }
}
