using Arctium.Connection.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Connection.Tls.Configuration
{
    public static class DefaultConfigurations
    {
        

        static DefaultConfigurations()
        {
        }

        public static Tls12ServerConfig CreateDefaultTls12ServerConfig()
        {
            Tls12ServerConfig config = new Tls12ServerConfig();

            config.EnableCipherSuites = new CipherSuite[]
            {
                //RSA Key Exchange
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                //CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                //CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
                //CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
                //
                ////ECDH Key exchange
                //CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                //CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            };

            return config;
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
