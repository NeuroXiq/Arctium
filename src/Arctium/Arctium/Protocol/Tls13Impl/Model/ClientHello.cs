using Arctium.Protocol.Tls13Impl.Model.Extensions;
using System;
using System.Collections.Generic;

namespace Arctium.Protocol.Tls13Impl.Model
{
    internal class ClientHello
    {
        public const ushort ProtocolVersion0x0303 = 0x0303;
        public static readonly byte[] ConstLegacyCompressionMethods = new byte[1] { 0 };

        public ushort ProtocolVersion;
        public byte[] Random;
        public byte[] LegacySessionId;
        public List<CipherSuite> CipherSuites;
        public byte[] LegacyCompressionMethods;
        public List<Extension> Extensions { get; set; }

        public ClientHello() { }

        public ClientHello(byte[] random, byte[] legacySessionId, CipherSuite[] suites, List<Extension> extensions)
        {
            ProtocolVersion = ProtocolVersion0x0303;
            LegacySessionId = legacySessionId;
            Random = random;
            CipherSuites = new List<CipherSuite>(suites);
            Extensions = extensions;
            LegacyCompressionMethods = ConstLegacyCompressionMethods;
        }

        public bool TryGetExtension<T>(ExtensionType type, out T outExtension) where T : Extension
        {
            foreach (var extension in Extensions)
            {
                if (extension.ExtensionType == type)
                {
                    outExtension = (T)extension;
                    return true;
                }
            }

            outExtension = null;
            return false;
        }

        public T GetExtension<T>(ExtensionType type) where T : Extension
        {
            T extension;

            if (!TryGetExtension(type, out extension))
            {
                throw new InvalidOperationException("Extension missing in list:  " + type.ToString());
            }

            return extension;
        }
    }
}
