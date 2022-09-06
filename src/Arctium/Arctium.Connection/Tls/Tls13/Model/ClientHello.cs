using Arctium.Connection.Tls.Tls13.Model.Extensions;
using System;

namespace Arctium.Connection.Tls.Tls13.Model
{
    internal class ClientHello
    {
        public ushort ProtocolVersion;
        public byte[] Random;
        public byte[] LegacySessionId;
        public CipherSuite[] CipherSuites;
        public byte[] LegacyCompressionMethods;
        public Extension[] Extensions { get; set; }

        public T GetExtension<T>(ExtensionType type) where T : Extension
        {
            foreach (var extension in Extensions)
            {
                if (extension.ExtensionType == type)
                    return (T)extension;
            }

            throw new InvalidOperationException("Extension missing in list");
        }
    }
}
