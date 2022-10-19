using Arctium.Standards.Connection.Tls.Tls13.Model;
using System;
using static Arctium.Standards.Connection.Tls.Tls13.Model.Extensions.SupportedGroupExtension;

namespace Arctium.Standards.Connection.Tls.Tls13.API
{
    public class Tls13ClientConfig
    {
        internal CipherSuite[] SupportedSuites { get; private set; }
        internal NamedGroup[] SupportedGroups { get; private set; }

        public static Tls13ClientConfig DefaultUnsafe()
        {
            var config = new Tls13ClientConfig();

            config.SupportedGroups = new NamedGroup[]
            {
                NamedGroup.X25519,
                // NamedGroup.Ffdhe2048,
                // NamedGroup.Ffdhe3072,
            };

            return config;
        }

        internal void ThrowIfInvalidState()
        {
        }
    }
}
