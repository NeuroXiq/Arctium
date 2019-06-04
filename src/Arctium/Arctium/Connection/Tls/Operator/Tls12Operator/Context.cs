using Arctium.Connection.Tls.CryptoConfiguration;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace Arctium.Connection.Tls.Operator.Tls12Operator
{
    //
    // Context class is updated dynamically after processing 
    // TLS messages routine. It contains all exchanged messages,
    // generated secrets, reders/writers etc. used in various 
    // points in handshake processing
    //

    class Context
    {
        public HandshakeMessages allHandshakeMessages;
        public HandshakeIO handshakeIO;
        public AppDataIO appDataIO;
        public Tls12Secrets secrets;
        public byte[] Premaster;

        ///<summary>Selected certificate sended to client/received from server</summary>
        public X509Certificate2 Certificate;
        
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
