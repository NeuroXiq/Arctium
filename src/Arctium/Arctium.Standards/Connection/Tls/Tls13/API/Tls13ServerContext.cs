﻿using Arctium.Standards.X509.X509Cert;

namespace Arctium.Standards.Connection.Tls.Tls13.API
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
    }
}
