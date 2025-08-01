using Arctium.Protocol.Tls.Tls12.CryptoFunctions;
using System.Security.Cryptography.X509Certificates;
using Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Enum;

namespace Arctium.Protocol.Tls.Tls12.Configuration
{
    public class Tls11ServerConfig
    {
        public delegate bool ClientAuthenticationDelegate(X509Certificate2[] certChain);

        public X509Certificate2[] Certificates;

        public bool AuthenticateClient;
        public ClientAuthenticationDelegate ClientAuthenticationHandler;

        public CipherSuite[] EnableCipherSuites;
    }
}
