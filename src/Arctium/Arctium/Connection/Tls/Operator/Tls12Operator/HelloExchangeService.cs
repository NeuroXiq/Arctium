using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using Arctium.CryptoFunctions;
using System;

namespace Arctium.Connection.Tls.Operator.Tls12Operator
{
    class HelloExchangeService
    {
        CipherSuite[] availableSuites;
        OnHandshakeState handshakeHandler;

        public HelloExchangeService(OnHandshakeState handler, CipherSuite[] suites)
        {
            this.availableSuites = suites;

            this.handshakeHandler = handler;
        }

        public void ExchangeHelloAsServer(HandshakeMessages12 messagesContext)
        {
            Handshake handshake = handshakeHandler.Read();
            if (handshake.MsgType != HandshakeType.ClientHello)
                throw new Exception("Expected client hello");


            ClientHello clientHello = (ClientHello)handshake;

            ServerHello serverHello = new ServerHello();

            serverHello.CipherSuite = FindSuite(clientHello);
            serverHello.CompressionMethod = CompressionMethod.NULL;
            serverHello.ProtocolVersion = new Protocol.ProtocolVersion(3, 3);
            serverHello.Random = GenerateRandom();
            serverHello.SessionID = GenerateSessionID();

            handshakeHandler.Write(serverHello);

            messagesContext.ClientHello = clientHello;
            messagesContext.ServerHello = serverHello;
        }

        private byte[] GenerateSessionID()
        {
            byte[] sesId = new byte[32];
            RandomGenerator random = new RandomGenerator();
            random.GenerateBytes(sesId, 0, 32);

            return sesId;
        }

        private byte[] GenerateRandom()
        {
            byte[] rand = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                rand[i] = (byte)(32 - i);
            }

            return rand;
        }

        private CipherSuite FindSuite(ClientHello clientHello)
        {
            foreach (CipherSuite suite in clientHello.CipherSuites)
            {
                foreach (CipherSuite available in availableSuites)
                {
                    if (available == suite) return suite;
                }
            }

            throw new Exception("All available cipher suites are not supported by client");
        }
    }
}
