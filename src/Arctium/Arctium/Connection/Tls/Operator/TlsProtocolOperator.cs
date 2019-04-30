using Arctium.Connection.Tls.Protocol;
using System.IO;
using System;
using Arctium.Rand;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using Arctium.Connection.Tls.Protocol.RecordProtocol;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer;
using System.Security.Cryptography.X509Certificates;
using Arctium.Connection.Tls.ProtocolStream.HighLevelLayer;
using Arctium.Connection.Tls.Crypto;
using Arctium.Connection.Tls.Protocol.BinaryOps;
using Arctium.Connection.Tls.Protocol.ChangeCipherSpecProtocol;

namespace Arctium.Connection.Tls.Operator
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
            RecordLayer recordStream = RecordLayer.Initialize(innerStream);
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

            //SecurityParameters secParams = GetStaticSecParams(clientHello, serverHello, clientKX.PreMasterSecret);



        }

        private SecurityParameters GetStaticSecParams(ClientHello ch, ServerHello sh, PremasterSecret premaster)
        {
            SecurityParameters secParams = new SecurityParameters();

            secParams.BulkCipherAlgorithm = BulkCipherAlgorithm.AES;
            secParams.CipherType = CipherType.Block;
            secParams.ClientRandom = GetHelloRandom(ch.Random);
            secParams.ServerRandom = GetHelloRandom(sh.Random);
            secParams.HashSize = 20;
            secParams.MACAlgorithm = MACAlgorithm.SHA;
            secParams.CompressionAlgorithm = CompressionMethod.NULL;
            secParams.Entity = ConnectionEnd.Server;
            secParams.KeySize = 16;
            secParams.KeyMaterialLength = 16;

            

            return secParams;
        }

        //
        // artifacts block start
        //


        private byte[] GetPremasterSecret(ClientKeyExchangeDecryptedRsa decryptedKX)
        {
            byte[] bytes = new byte[48];
            bytes[0] = decryptedKX.PreMasterSecret.ClientVersion.Major;
            bytes[1] = decryptedKX.PreMasterSecret.ClientVersion.Minor;

            Array.Copy(decryptedKX.PreMasterSecret.Random, 0, bytes, 2, 46);

            return bytes;
        }

        private byte[] GetHelloRandom(HelloRandom random)
        {
            byte[] bytes = new byte[4 + random.RandomBytes.Length];


            NumberConverter.FormatUInt32(random.GmtUnixTime, bytes, 0);
            Array.Copy(random.RandomBytes, 0, bytes, 4, random.RandomBytes.Length);

            return bytes;
        }




        //
        // artifacts block end
        //


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
                    if(availableCompressions[j] == clientHello.CompressionMethods[i])
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

            ContentType type;
            object obj = highLevelProtocolStream.Read(out type);

            return (Handshake)obj;
        }

        private ChangeCipherSpec ReadOnlyChangeCipherSpec()
        {
            ContentType contentType;
            object o = highLevelProtocolStream.Read(out contentType);

            return (ChangeCipherSpec)o;
        }
    }
}
