using Arctium.Connection.Tls.CryptoConfiguration;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12;
using System.IO;

namespace Arctium.Connection.Tls.Operator.Tls12Operator
{
    class Context
    {
        public HandshakeMessages allHandshakeMessages;
        public HandshakeIO handshakeIO;
        public AppDataIO appDataIO;
        public Tls12Secrets secrets;
        
        public RecordLayer12 recordLayer;

        public Context(Stream recordLayerInnerStream)
        {
            recordLayer = RecordLayer12.Initialize(recordLayerInnerStream);
            handshakeIO = new HandshakeIO(recordLayer);
            appDataIO = new AppDataIO(recordLayer);
            allHandshakeMessages = new HandshakeMessages();
            secrets = new Tls12Secrets();
        }
    }
}
