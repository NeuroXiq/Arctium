using Arctium.Connection.Tls.Protocol.AlertProtocol;
using Arctium.Connection.Tls.Protocol.BinaryOps.Formatter;
using Arctium.Connection.Tls.Protocol.ChangeCipherSpecProtocol;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using Arctium.Connection.Tls.ProtocolStream.HighLevelLayer;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer11;
using Arctium.CryptoFunctions;
using System;

namespace Arctium.Connection.Tls.Operator.Tls11Operator
{
    class Tls11ClientOperator : TlsProtocolOperator
    {
        RecordLayer11 recordLayer;
        HandshakeStack handshakeStack;
        HighLevelProtocolStream protocol;

        Handshake currentHandshakeMessage;
        HandshakeMessages11 allMessages;

        private Tls11ClientOperator(RecordIO recordIO)
        {
            recordLayer = RecordLayer11.Initialize(recordIO);
            protocol = new HighLevelProtocolStream(recordLayer);
            handshakeStack = new HandshakeStack();
        }

        public static Tls11ClientOperator Initialize(RecordIO recordIO)
        {
            recordIO.RecordVersion = new Protocol.ProtocolVersion(3, 2);
            return new Tls11ClientOperator(recordIO);
        }

        private void FatalAlert(Alert a) { throw new Exception("Alert fatal"); }
        private void FatalApplicationData(byte[] buffer, int offset, int length) { throw new Exception("fatal app data"); }
        private void FatalCCS(ChangeCipherSpec ccs) { throw new Exception("fatal ccs"); }

        public void OpenNewSession()
        {
            protocol.AlertHandler += FatalAlert;
            protocol.ApplicationDataHandler += FatalApplicationData;
            protocol.ChangeCipherSpecHandler += FatalCCS;
            protocol.HandshakeHandler += ReadHandshakeAndCache;

            SendClientHello();

            protocol.Read();
            GetServerHello();
            GetCertifiate();
            GetServerKeyExchange();
            GetCertifiateExchange();
            GetServerHelloDone();

            SendCertifiate();
            SendClientKeyExchange();
            SendCertifiateVerify();
            SendChangeCipherSpec();
            SendFinished();

            GetFinished();
            ExchangeApplicationData();
        }

        private void ReadHandshakeAndCache(Handshake message, byte[] rawBytes)
        {
            handshakeStack.Push(rawBytes, message.MsgType, HandshakeStack.TransmitType.Received);
            currentHandshakeMessage = message;
        }

        private void ExchangeApplicationData()
        {
            
        }

        private byte[] GetSessionID()
        {
            byte[] sesId = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                sesId[i] = (byte)i;
            }

            return sesId;
        }

        private byte[] GetHelloRandom()
        {
            byte[] hr = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                hr[i] = (byte)(31 - i);
            }

            return hr;
        }

        private void GetFinished()
        {
            throw new NotImplementedException();
        }

        private void SendFinished()
        {
            throw new NotImplementedException();
        }

        private void SendChangeCipherSpec()
        {
            throw new NotImplementedException();
        }

        private void SendCertifiateVerify()
        {
            throw new NotImplementedException();
        }

        private void SendClientKeyExchange()
        {
            throw new NotImplementedException();
        }

        private void SendCertifiate()
        {
            throw new NotImplementedException();
        }

        private void GetServerHelloDone()
        {
            throw new NotImplementedException();
        }

        private void GetCertifiateExchange()
        {
            throw new NotImplementedException();
        }

        private void GetServerKeyExchange()
        {
            throw new NotImplementedException();
        }

        private void GetCertifiate()
        {
            if (currentHandshakeMessage.MsgType != HandshakeType.Certificate)
                throw new Exception("expected certificate");

            protocol.Read();
        }

        private void GetServerHello()
        {
            if (currentHandshakeMessage.MsgType != HandshakeType.ServerHello) throw new Exception("expected server hello");
            allMessages.ServerHello = (ServerHello)currentHandshakeMessage;

            protocol.Read();
        }

        private void SendClientHello()
        {
            ClientHello hello = new ClientHello();
            hello.CipherSuites = new CipherSuite[] { CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA};
            hello.ClientVersion = new Protocol.ProtocolVersion(3, 2);
            hello.CompressionMethods = new CompressionMethod[] { CompressionMethod.NULL };
            hello.MsgType = HandshakeType.ClientHello;
            hello.Random = GetHelloRandom();
            hello.SessionID = GetSessionID();

            RandomGenerator rg = new RandomGenerator();
            rg.GenerateBytes(hello.Random, 0, 32);
            rg.GenerateBytes(hello.SessionID, 0, 32);

            WriteAndCacheMessage(hello);
        }

        private void WriteAndCacheMessage(Handshake msg)
        {
            protocol.Write(msg);

            HandshakeFormatter f = new HandshakeFormatter();
            byte[] asdf = f.GetBytes(msg);

            handshakeStack.Push(asdf, msg.MsgType, HandshakeStack.TransmitType.Sended);
        }

        public override void WriteApplicationData(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }

        public override int ReadApplicationData(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }
    }
}
