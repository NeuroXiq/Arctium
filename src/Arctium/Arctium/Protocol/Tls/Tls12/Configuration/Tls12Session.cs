using Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Enum;

namespace Arctium.Protocol.Tls.Tls12.Configuration
{
    public class Tls12Session
    {
        public byte[] SessionID;
        public CipherSuite SelectedCipherSuite;

        internal byte[] MasterSecret;
    }
}
