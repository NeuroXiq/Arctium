﻿using Arctium.Protocol.Tls.Tls12.CryptoConfiguration;
using Arctium.Protocol.Tls.Protocol;
using Arctium.Protocol.Tls.Protocol.ChangeCipherSpecProtocol;
using Arctium.Protocol.Tls.Protocol.HandshakeProtocol;
using Arctium.Protocol.Tls.Tls12.ProtocolStream.HighLevelLayer;
using System.Collections.Generic;
using Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Enum;

namespace Arctium.Protocol.Tls.Tls12.Operator.Tls11Operator
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
