using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using System;

namespace Arctium.Connection.Tls.Configuration
{
    public static class DefaultConfigurations
    {
        

        static DefaultConfigurations()
        {
        }

        public static Tls11ServerConfig CreateDefaultTls11ServerConfig()
        {
            Tls11ServerConfig tls11ServerConfig = new Tls11ServerConfig();

            tls11ServerConfig.AuthenticateClient = false;
            tls11ServerConfig.ClientAuthenticationHandler = null;
            tls11ServerConfig.Certificates = null;

            tls11ServerConfig.EnableCipherSuites = new CipherSuite[]
            {
                //CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                //CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
            };

            return tls11ServerConfig;
        }
    }
}
