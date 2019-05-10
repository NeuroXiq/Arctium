using System.Security.Cryptography.X509Certificates;

namespace Arctium.Connection.Tls
{
    public class TlsServerConfiguration
    {
        public X509Certificate2 X509Certificate;

        public Tls11ServerConfiguration Tls11ServerConfig;
        public Tls12ServerConfiguration Tls12ServerConfig;
        public Tls13ServerConfiguration Tls13ServerConfig;
    }
}
