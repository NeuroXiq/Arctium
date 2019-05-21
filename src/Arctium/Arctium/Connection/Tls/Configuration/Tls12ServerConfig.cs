using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using System.Security.Cryptography.X509Certificates;

namespace Arctium.Connection.Tls.Configuration
{
    public class Tls12ServerConfig
    {
        public X509Certificate2[] Certificates;
        public CipherSuite[] EnableCipherSuites;

        //TODO tls12serverconfig
        public object clientVerification;
        public object extensions;
        public object SessionCache;
        
    }
}
