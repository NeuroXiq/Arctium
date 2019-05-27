using Arctium.Connection.Tls.CryptoConfiguration;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12;

namespace Arctium.Connection.Tls.Operator.Tls12Operator
{
    class Context
    {
        public HandshakeMessages allHandshakeMessages;
        public HandshakeIO handshakeIO;
        public AppDataIO appDataIO;
        public Tls12Secrets secrets;

        public Context(RecordLayer12 recordLayer)
        {
            handshakeIO = new HandshakeIO(recordLayer);
            appDataIO = new AppDataIO(recordLayer);
            allHandshakeMessages = new HandshakeMessages();
        }
    }
}
