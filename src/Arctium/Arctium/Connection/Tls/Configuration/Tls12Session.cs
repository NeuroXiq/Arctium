using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12;

namespace Arctium.Connection.Tls.Configuration
{
    public class Tls12Session
    {
        public byte[] SessionID;
        public CipherSuite SelectedCipherSuite;

        internal RecordLayer12Params readParams;
        internal RecordLayer12Params writeParams;
    }
}
