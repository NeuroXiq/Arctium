using Arctium.Connection.Tls.Configuration.TlsExtensions;
using Arctium.Connection.Tls.CryptoConfiguration;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using System.Security.Cryptography.X509Certificates;

namespace Arctium.Connection.Tls.Configuration
{
    public class Tls12ServerConfig
    {
        public X509Certificate2[] Certificates;
        public CipherSuite[] EnableCipherSuites;
        public TlsHandshakeExtension[] HandshakeExtensions;

        //TODO tls12serverconfig
        public object clientVerification;
        public object SessionCache;
        public object enableRenegotiation;
        
        
    }
}
