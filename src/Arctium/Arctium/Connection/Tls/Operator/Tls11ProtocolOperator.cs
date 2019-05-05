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

namespace Arctium.Connection.Tls.Operator
{
    class Tls11ProtocolOperator : TlsProtocolOperator
    {
        RecordLayer11 recordProtocolStream;
        HighLevelProtocolStream highLevelProtocolStream;
        ConnectionEnd entity;

        Tls11ProtocolOperator(RecordLayer11 recordProtocolStream, ConnectionEnd entity)
        {
            this.recordProtocolStream = recordProtocolStream;
            highLevelProtocolStream = new HighLevelProtocolStream(recordProtocolStream);
            this.entity = entity;
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

            ClientHello clientHello = ReadOnlyHandshake() as ClientHello;
            if (clientHello == null) throw new HandshakeException("Invalid Handshake message order. Expected client hello");

            ServerHello serverHello = NegotiateServerHello(clientHello);
            highLevelProtocolStream.Write(serverHello);

            Certificate certMsg = new Certificate(new X509Certificate2("D:\\test.pfx", "test"));
            highLevelProtocolStream.Write(certMsg);

            ServerHelloDone serverHelloDone = new ServerHelloDone();
            highLevelProtocolStream.Write(serverHelloDone);

            ClientKeyExchange clientKeyEx = ReadOnlyHandshake() as ClientKeyExchange;
            if (clientKeyEx == null) throw new HandshakeException("Invalid Handshake message order. Expected client key exchange");

            KeyExchangeRsaCrypto rsaDecryp = new KeyExchangeRsaCrypto();
            ClientKeyExchangeDecryptedRsa clientKX = rsaDecryp.Decrypt(clientKeyEx, certMsg.ANS1Certificate);

            ChangeCipherSpec ccs = ReadOnlyChangeCipherSpec();

            CryptoSuite oopSuite = CryptoSuites.Get(serverHello.CipherSuite);

            byte[] premaster = clientKX.PreMasterSecret.RawBytes;

            SecretGenerator g = new SecretGenerator();
            SecretGenerator.SecParams11Seed sps = new SecretGenerator.SecParams11Seed();
            sps.ClientRandom = clientHello.Random.RawBytes;
            sps.ServerRandom = serverHello.Random.RawBytes;
            sps.CompressionMethod = CompressionMethod.NULL;
            sps.HostType = ConnectionEnd.Server;
            sps.Premaster = clientKX.PreMasterSecret.RawBytes;
            sps.RecordCryptoType = oopSuite.RecordCryptoType;

            SecParams11 secParams = g.GenerateSecParams11(sps);

            highLevelProtocolStream.Write(new ChangeCipherSpec() { CCSType = ChangeCipherSpecType.ChangeCipherSpec });
            highLevelProtocolStream.UpdateRecordLayer(secParams);

            Finished finished = (Finished)ReadOnlyHandshake();
            

            HandshakeFormatter formatter = new HandshakeFormatter();

            Finished f = new Finished(new byte[12]);

            highLevelProtocolStream.Write(f);
            ReadOnlyHandshake();
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

        private Handshake ReadOnlyHandshake()
        {

            ContentType type = ContentType.Alert;
            object obj = null;
            while (type != ContentType.Handshake)
            {
                obj = highLevelProtocolStream.Read(out type);
                if (type == ContentType.Alert) throw new Exception("alert");
            }

            return (Handshake)obj;
        }

        private ChangeCipherSpec ReadOnlyChangeCipherSpec()
        {
            ContentType contentType;
            object o = highLevelProtocolStream.Read(out contentType);

            return (ChangeCipherSpec)o;
        }

        public override void WriteApplicationData(byte[] buffer, int offset, int length)
        {
            throw new NotImplementedException();
        }

        public override void ReadApplicationData(byte[] buffer, int offset, int length)
        {
            throw new NotImplementedException();
        }
    }
}
