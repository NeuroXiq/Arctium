using Arctium.Standards.X509.X509Cert;

namespace Arctium.Standards.Connection.Tls13
{
    public class Tls13ServerContext
    {
        public Tls13ServerConfig Config { get; private set; }

        public Tls13ServerContext(Tls13ServerConfig config)
        {
            config.ThrowIfInvalidObjectState();
            Config = config;
        }

        public static Tls13ServerContext Default(X509CertWithKey[] certificates)
        {
            var config = Tls13ServerConfig.Default(certificates);
            var context = new Tls13ServerContext(config);

            return context;
        }

        internal static Tls13ServerContext QuicIntegrationDefault(X509CertWithKey[] certificates)
        {
            var config = Tls13ServerConfig.Default(certificates);
            config.ConfigureQuicIntegration(true);
            var context = new Tls13ServerContext(config);

            return context;
        }
    }
}
