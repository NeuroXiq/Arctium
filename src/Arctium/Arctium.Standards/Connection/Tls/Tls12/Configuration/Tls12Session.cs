using Arctium.Standards.Connection.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Standards.Connection.Tls.Tls12.Configuration
{
    public class Tls12Session
    {
        public byte[] SessionID;
        public CipherSuite SelectedCipherSuite;

        internal byte[] MasterSecret;
    }
}
