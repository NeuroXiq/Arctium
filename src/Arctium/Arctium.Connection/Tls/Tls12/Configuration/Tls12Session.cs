using Arctium.Connection.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Connection.Tls.Tls12.Configuration
{
    public class Tls12Session
    {
        public byte[] SessionID;
        public CipherSuite SelectedCipherSuite;

        internal byte[] MasterSecret;
    }
}
