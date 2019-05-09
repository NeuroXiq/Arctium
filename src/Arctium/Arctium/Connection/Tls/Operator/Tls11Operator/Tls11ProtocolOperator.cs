using Arctium.Connection.Tls.Protocol;
using System.IO;
using System;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using Arctium.Connection.Tls.Protocol.RecordProtocol;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer;
using System.Security.Cryptography.X509Certificates;
using Arctium.Connection.Tls.ProtocolStream.HighLevelLayer;
using Arctium.Connection.Tls.Protocol.ChangeCipherSpecProtocol;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer11;
using Arctium.Connection.Tls.CryptoFunctions;
using Arctium.Connection.Tls.CryptoConfiguration;
using Arctium.CryptoFunctions;
using Arctium.Connection.Tls.Protocol.BinaryOps.Formatter;
using Arctium.Connection.Tls.Buffers;
using System.Security.Cryptography;
using Arctium.Connection.Tls.Protocol.AlertProtocol;
using System.Collections.Generic;

namespace Arctium.Connection.Tls.Operator.Tls11Operator
{
    class Tls11ProtocolOperator : TlsProtocolOperator
    {
        RecordLayer11 recordProtocolStream;
        HighLevelProtocolStream highLevelProtocolStream;
        ConnectionEnd entity;
        HandshakeFormatter handshakeFormatter = new HandshakeFormatter();

        Tls11HandshakeState handshakeState;

        byte[] internalApplicationDataBuffer = new byte[123];
        int applicationDataLength = 0;

        Tls11ProtocolOperator(RecordLayer11 recordProtocolStream, ConnectionEnd entity)
        {
            this.recordProtocolStream = recordProtocolStream;
            highLevelProtocolStream = new HighLevelProtocolStream(recordProtocolStream);
            this.entity = entity;
            handshakeState = new Tls11HandshakeState();
            handshakeState.Reset();
        }

        public static Tls11ProtocolOperator CreateServerSession(RecordIO recordIo)
        {
            recordIo.RecordVersion = new ProtocolVersion(3, 2);
            RecordLayer11 recordLayer = RecordLayer11.Initialize(recordIo);
            Tls11ProtocolOperator tlsOperator = new Tls11ProtocolOperator(recordLayer, ConnectionEnd.Server);
            tlsOperator.HandshakeAsServer();
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
            //
            //
            //
            HighLevelProtocolStream.ReadedChangecipherSpecCallback cipherspecExceptionHandler = (c) => { throw new Exception("ccs invalid order, fatal"); };
            HighLevelProtocolStream.ReadedAlertCallback alertInHandshakeFatal = delegate (Alert alert) { throw new Exception("Alert in handshake, fatal"); };

            highLevelProtocolStream.AlertHandler += alertInHandshakeFatal;
            highLevelProtocolStream.ChangeCipherSpecHandler += cipherspecExceptionHandler;
            highLevelProtocolStream.HandshakeHandler += ServerHandshakeProcessor;
            handshakeState.Reset();

            handshakeState.NextExpectedRead = HandshakeType.ClientHello;

            while (!handshakeState.HandshakeEnd)
            {
                if (handshakeState.NextExpectedRead == HandshakeType.Finished)
                {
                    highLevelProtocolStream.ChangeCipherSpecHandler -= cipherspecExceptionHandler;
                    highLevelProtocolStream.ChangeCipherSpecHandler += HandshakeChangeCipherSpec;
                }
                highLevelProtocolStream.Read();
            }
            highLevelProtocolStream.AlertHandler -= alertInHandshakeFatal;
            highLevelProtocolStream.ChangeCipherSpecHandler -= HandshakeChangeCipherSpec;

            highLevelProtocolStream.AlertHandler += (a) => { throw new Exception("after handshake alter exteption: " + a.Description.ToString()); };
            //highLevelProtocolStream.Read();

            highLevelProtocolStream.ApplicationDataHandler += LoadApplicationData;


        }

        private void LoadApplicationData(byte[] buffer, int offset, int length)
        {

            if (length > internalApplicationDataBuffer.Length) internalApplicationDataBuffer = new byte[length];
            applicationDataLength = length;
            Buffer.BlockCopy(buffer, offset, internalApplicationDataBuffer, 0, length);


        }

        private void HandshakeChangeCipherSpec(ChangeCipherSpec changeCipherSpec)
        {
            CryptoSuite oopSuite = CryptoSuites.Get(handshakeState.ServerHello.CipherSuite);

            KeyExchangeRsaCrypto rsaDecryp = new KeyExchangeRsaCrypto();
            ClientKeyExchangeDecryptedRsa clientKX = rsaDecryp.Decrypt(handshakeState.ClientKeyExchange, handshakeState.ServerCertificate.ANS1Certificate);
            byte[] premaster = clientKX.PreMasterSecret.RawBytes;

            SecretGenerator g = new SecretGenerator();
            SecretGenerator.SecParams11Seed sps = new SecretGenerator.SecParams11Seed();
            sps.ClientRandom = handshakeState.ClientHello.Random.RawBytes;
            sps.ServerRandom = handshakeState.ServerHello.Random.RawBytes;
            sps.CompressionMethod = CompressionMethod.NULL;
            sps.HostType = ConnectionEnd.Server;
            sps.Premaster = clientKX.PreMasterSecret.RawBytes;
            sps.RecordCryptoType = oopSuite.RecordCryptoType;

            SecParams11 secParams = g.GenerateSecParams11(sps);

            highLevelProtocolStream.Write(new ChangeCipherSpec() { CCSType = ChangeCipherSpecType.ChangeCipherSpec });
            highLevelProtocolStream.UpdateRecordLayer(secParams);
            handshakeState.SecParams = secParams;
        }

        private void ServerHandshakeProcessor(Handshake message, byte[] rawBytes)
        {
            if(handshakeState.NextExpectedRead != message.MsgType)
            {
                throw new Exception("Unexpected message type");
            }

            handshakeState.AllHandshakedMessagesBytes.Add(rawBytes);
            switch (message.MsgType)
            {
                case HandshakeType.ClientHello:
                    //handshakeState.AllHandshakedMessagesBytes.Add(rawBytes);
                    DoClientHello(message as ClientHello);
                    break;
                case HandshakeType.ClientKeyExchange:
                    //handshakeState.AllHandshakedMessagesBytes.Add(rawBytes);
                    DoClientKeyExchange(message as ClientKeyExchange);
                    break;
                case HandshakeType.Finished:
                    DoServerFinished(message as Finished);
                    break;
                default: throw new NotImplementedException("this is not simple and classic handshake");
            }

        }

        private void DoServerFinished(Finished finished)
        {
            handshakeState.HandshakeEnd = true;

            //work to this point
            PseudoRandomFunction prf = new PseudoRandomFunction();
            MD5 md5 = MD5.Create();
            SHA1 sha1 = SHA1.Create();

            List<byte[]> checkClientFinished = new List<byte[]>();
            //to check client finished is needed to ignore last finished message because client do not include them in calculations
            for (int i = 0; i < handshakeState.AllHandshakedMessagesBytes.Count - 1; i++)
            {
                checkClientFinished.Add(handshakeState.AllHandshakedMessagesBytes[i]);
            }
            byte[] toCheckClient = BufferTools.Join(checkClientFinished.ToArray());

            byte[] md5ReceivedHash = md5.ComputeHash(toCheckClient);
            byte[] sha1ReceivedHash = sha1.ComputeHash(toCheckClient);

            byte[] hashesSeed = BufferTools.Join(md5ReceivedHash, sha1ReceivedHash);

            byte[] res = prf.Prf(handshakeState.SecParams.MasterSecret, "client finished", hashesSeed, 12);

            if (!BufferTools.IsContentEqual(res, finished.VerifyData)) throw new Exception("Invalid finished messages");

            byte[] toSendHashSeed = BufferTools.Join(handshakeState.AllHandshakedMessagesBytes.ToArray());
            byte[] md5ToSendSeed = md5.ComputeHash(toSendHashSeed);
            byte[] sha1ToSendSeed = sha1.ComputeHash(toSendHashSeed);

            byte[] prfToSendSeed = BufferTools.Join(md5ToSendSeed, sha1ToSendSeed);

            byte[] toSendVerifyData = prf.Prf(handshakeState.SecParams.MasterSecret, "server finished", prfToSendSeed, 12);

            Finished toSendFinished = new Finished(toSendVerifyData);

            highLevelProtocolStream.Write(toSendFinished);

            handshakeState.HandshakeEnd = true;

            //throw new NotImplementedException();
        }

        private void DoClientKeyExchange(ClientKeyExchange clientKeyExchange)
        {
            handshakeState.ClientKeyExchange = clientKeyExchange;

            handshakeState.NextExpectedRead = HandshakeType.Finished;

            
        }

        private void DoClientHello(ClientHello clientHello)
        {
            ServerHello serverHello = NegotiateServerHello(clientHello);
            highLevelProtocolStream.Write(serverHello);

            handshakeState.ClientHello = clientHello;
            handshakeState.ServerHello = serverHello;
            handshakeState.AllHandshakedMessagesBytes.Add(handshakeFormatter.GetBytes(serverHello));


            Certificate certMsg = new Certificate(new X509Certificate2("D:\\test.pfx", "test"));
            highLevelProtocolStream.Write(certMsg);
            handshakeState.ServerCertificate = certMsg;
            handshakeState.AllHandshakedMessagesBytes.Add(handshakeFormatter.GetBytes(certMsg));

            ServerHelloDone serverHelloDone = new ServerHelloDone();
            handshakeState.ServerHelloDone = serverHelloDone;
            highLevelProtocolStream.Write(serverHelloDone);
            handshakeState.AllHandshakedMessagesBytes.Add(handshakeFormatter.GetBytes(serverHelloDone));

            handshakeState.NextExpectedRead = HandshakeType.ClientKeyExchange;
        }

        private ServerHello NegotiateServerHello(ClientHello clientHello)
        {
            ServerHello serverHello = new ServerHello();

            CipherSuite[] availableCiphers = new CipherSuite[] { CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA };
            CompressionMethod[] availableCompressions = new CompressionMethod[] { CompressionMethod.NULL };

            CipherSuite negotiatedCipher = CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA;
            //CipherSuite negotiatedCipher = CipherSuite.TLS_AES_128_CCM_8_SHA256;
            CompressionMethod negotiatedCompression = CompressionMethod.NULL;

            bool negotiationOk = false;

            for (int i = 0; i < clientHello.CipherSuites.Length; i++)
                for (int j = 0; j < availableCiphers.Length; j++)
                {
                    if (availableCiphers[j] == clientHello.CipherSuites[i])
                    {
                        negotiatedCipher = availableCiphers[j];
                        negotiationOk = true;
                        break;
                    }
                }

            for (int i = 0; i < clientHello.CompressionMethods.Length; i++)
                for (int j = 0; j < availableCompressions.Length; j++)
                {
                    if (availableCompressions[j] == clientHello.CompressionMethods[i])
                    {
                        negotiatedCompression = availableCompressions[j];
                        negotiationOk &= true;
                        break;
                    }
                }

            if (!negotiationOk) throw new Exception("Cannot negotiate client hello");


            serverHello.CipherSuite = negotiatedCipher;
            serverHello.CompressionMethod = negotiatedCompression;
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

        public override void WriteApplicationData(byte[] buffer, int offset, int length)
        {
            highLevelProtocolStream.WriteApplicationData(buffer, offset, length);
        }

        public override int ReadApplicationData(byte[] buffer, int offset, int length)
        {
            if(applicationDataLength < 1)
                highLevelProtocolStream.Read();

            int toRead = applicationDataLength > length ? length : applicationDataLength;

            Buffer.BlockCopy(internalApplicationDataBuffer, 0, buffer, offset, toRead);

            applicationDataLength -= toRead;

            return toRead;
        }
    }
}
