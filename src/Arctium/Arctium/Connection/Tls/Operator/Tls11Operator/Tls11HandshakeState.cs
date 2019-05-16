using Arctium.Connection.Tls.CryptoConfiguration;
using Arctium.Connection.Tls.Protocol;
using Arctium.Connection.Tls.Protocol.ChangeCipherSpecProtocol;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using Arctium.Connection.Tls.ProtocolStream.HighLevelLayer;
using System.Collections.Generic;

namespace Arctium.Connection.Tls.Operator.Tls11Operator
{
    class Tls11HandshakeState
    {
        public ClientHello ClientHello;
        public ServerHello ServerHello;
        public Certificate ServerCertificate;
        public ServerKeyExchange ServerKeyExchage;
        public CertificateRequest CertificateRequset;
        public ServerHelloDone ServerHelloDone;

        public Certificate ClientCertificate;
        public ClientKeyExchange ClientKeyExchange;
        public CertificateVerify CertificateVerify;

        public Finished ClientFinished;
        public Finished ServerFinished;

        public List<byte[]> AllHandshakedMessagesBytes;

        public HandshakeType NextExpectedRead;
        public bool HandshakeEnd;
        public SecParams11 SecParams;
        //
        //public HighLevelProtocolStream.ReadedAlertCallback AlertHandler;
        //public HighLevelProtocolStream.ReadedApplicationDataCallback ApplicationDataHandler;
        //public HighLevelProtocolStream.ReadedChangecipherSpecCallback ChangeCipherSpecHandler;
        //public HighLevelProtocolStream.ReadedHandshakeCallback HandshakeHandler;

        public Tls11HandshakeState()
        {
            AllHandshakedMessagesBytes = new List<byte[]>();
        }

        public void PushRawBytes(byte[] bytes)
        {
            AllHandshakedMessagesBytes.Add(bytes);
        }

        public void Reset()
        {
            ClientHello = null;
            ServerHello = null;
            ServerCertificate = null;
            ServerKeyExchage = null;
            CertificateRequset = null;
            ServerHelloDone = null;

            ClientCertificate = null;
            ClientKeyExchange = null;
            CertificateVerify = null;
            ClientFinished = null;
            ServerFinished = null;

            AllHandshakedMessagesBytes.Clear();

            //AlertHandler = null;
            //ApplicationDataHandler = null;
            //ChangeCipherSpecHandler = null;
            //HandshakeHandler = null;

            HandshakeEnd = false;
        }
    }
}
