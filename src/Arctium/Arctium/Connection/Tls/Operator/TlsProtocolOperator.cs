using Arctium.Connection.Tls.Protocol;
using System.IO;
using System;
using Arctium.Rand;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using Arctium.Connection.Tls.Protocol.RecordProtocol;
using Arctium.Connection.Tls.ProtocolStream;

namespace Arctium.Connection.Tls.Crypto
{
    class TlsProtocolOperator
    {
        RecordLayer recordProtocolStream;
        HighLevelProtocolStream highLevelProtocolStream;
        ConnectionEnd entity;

        TlsProtocolOperator(RecordLayer recordProtocolStream, ConnectionEnd entity)
        {
            this.recordProtocolStream = recordProtocolStream;
            highLevelProtocolStream = new HighLevelProtocolStream(recordProtocolStream);
            this.entity = entity;
        }

        public static TlsProtocolOperator CreateServerSession(Stream innerStream)
        {
            SecurityParametersFactory secParamsFactory = new SecurityParametersFactory();
            SecurityParameters secParams = secParamsFactory.BuildInitialState(ConnectionEnd.Server);
            RecordLayer recordStream = RecordLayer.Initialize(innerStream, ConnectionEnd.Server);
            TlsProtocolOperator tlsOperator = new TlsProtocolOperator(recordStream, ConnectionEnd.Server);

            return tlsOperator;
        }

        public void Handshake()
        {
            if (entity == ConnectionEnd.Server)
            {
                HandshakeAsServer();
            }
            else throw new NotSupportedException();
        }

        private void HandshakeAsServer()
        {
            ClientHello clientHello = ReadOnlyHandshake() as ClientHello;
            if (clientHello == null) throw new HandshakeException("Invalid Handshake message order. Expected client hello but received: " + clientHello.MsgType);

            Handshake serverHello = NegotiateServerHello(clientHello);
            highLevelProtocolStream.Write(serverHello);
            
        }

        private Handshake NegotiateServerHello(ClientHello clientHello)
        {
            ServerHello serverHello = new ServerHello();
            bool ok = false;

            CipherSuite enableCipher = CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA;
            CompressionMethod enableCompression = CompressionMethod.NULL;

            foreach (CipherSuite cs in clientHello.CipherSuites)
            {
                if (cs == enableCipher)
                {
                    ok = true;
                    break;
                }
            }
            foreach (CompressionMethod cm in clientHello.CompressionMethods)
            {
                if (cm == CompressionMethod.NULL)
                {
                    ok &= true;
                    break;
                }
            }

            if (!ok) throw new Exception("compression or suite not enable");


            serverHello.CipherSuite = enableCipher;
            serverHello.CompressionMethod = enableCompression;
            serverHello.ProtocolVersion = new ProtocolVersion(3, 2);
            serverHello.Random = GenerateHelloRandom();
            serverHello.SessionID = GenerateSessionID();


            return serverHello;
        }

        private SessionID GenerateSessionID()
        {
            RandomGenerator rg = new RandomGenerator();

            byte[] sidBytes = new byte[32];
            rg.GenerateBytes(sidBytes, 0, 32);

            return new SessionID(sidBytes);

        }

        private HelloRandom GenerateHelloRandom()
        {
            byte[] randomBytes = new byte[28];
            RandomGenerator rg = new RandomGenerator();
            rg.GenerateBytes(randomBytes, 0, 28);

            uint unixTime = (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            return new HelloRandom(unixTime, randomBytes);
        }

        private Handshake ReadOnlyHandshake()
        {

            ContentType type;
            object obj = highLevelProtocolStream.Read(out type);

            return (Handshake)obj;
        }

    }
}
