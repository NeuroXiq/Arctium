using Arctium.Connection.Tls.CryptoConfiguration;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12;

namespace Arctium.Connection.Tls.Operator.Tls12Operator
{
    class Context
    {
        public HandshakeMessages allHandshakeMessages;
        public HandshakeIO handshakeIO;
        public Tls12Secrets secrets;

        public Context(RecordLayer12 recordLayer)
        {
            handshakeIO = new HandshakeIO(recordLayer);
            allHandshakeMessages = new HandshakeMessages();
        }
    }
}
