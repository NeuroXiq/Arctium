using Arctium.Connection.Tls.Tls13.Model.Extensions;

namespace Arctium.Connection.Tls.Tls13.Model
{
    internal class ClientHello
    {
        public ushort ProtocolVersion;
        public byte[] Random;
        public byte[] LegacySessionId;
        public byte[] CipherSuites;
        public byte[] LegacyCompressionMethods;
        public Extension[] Extensions { get; set; }
    }
}
