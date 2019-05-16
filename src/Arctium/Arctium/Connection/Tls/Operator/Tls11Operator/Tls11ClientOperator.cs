using Arctium.Connection.Tls.Buffers;
using Arctium.Connection.Tls.CryptoConfiguration;
using Arctium.Connection.Tls.CryptoFunctions;
using Arctium.Connection.Tls.Protocol;
using Arctium.Connection.Tls.Protocol.AlertProtocol;
using Arctium.Connection.Tls.Protocol.BinaryOps.Formatter;
using Arctium.Connection.Tls.Protocol.ChangeCipherSpecProtocol;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using Arctium.Connection.Tls.ProtocolStream.HighLevelLayer;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer11;
using Arctium.CryptoFunctions;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Arctium.Connection.Tls.Operator.Tls11Operator
{
    class Tls11ClientOperator : TlsProtocolOperator
    {
        RecordLayer11 recordLayer;
        HandshakeStack handshakeStack;
        HighLevelProtocolStream protocol;

        Handshake currentHandshakeMessage;
        HandshakeMessages11 allMessages;
        SecParams11 secParams;

        private byte[] appDataBuffer;
        private int appDataOffset;
        private int appDataLength;

        private Tls11ClientOperator(RecordIO recordIO)
        {
            recordLayer = RecordLayer11.Initialize(recordIO);
            protocol = new HighLevelProtocolStream(recordLayer);
            handshakeStack = new HandshakeStack();
            allMessages = new HandshakeMessages11();
        }

        public static Tls11ClientOperator Initialize(RecordIO recordIO)
        {
            recordIO.RecordVersion = new Protocol.ProtocolVersion(3, 2);
            return new Tls11ClientOperator(recordIO);
        }

        private void FatalAlert(Alert a) { throw new Exception("Alert fatal"); }
        private void FatalApplicationData(byte[] buffer, int offset, int length) { throw new Exception("fatal app data"); }
        private void FatalCCS(ChangeCipherSpec ccs) { throw new Exception("fatal ccs"); }
        private void FatalHandshake(Handshake h, byte[] b) { throw new Exception("unexpected hanbdshake msg"); }

        public void OpenNewSession()
        {
            protocol.AlertHandler += FatalAlert;
            protocol.ApplicationDataHandler += FatalApplicationData;
            protocol.ChangeCipherSpecHandler += FatalCCS;
            protocol.HandshakeHandler += ReadHandshakeAndCache;

            SendClientHello();

            //start reading process
            protocol.Read();

            GetServerHello();
            GetCertifiate();
            GetServerKeyExchange();
            GetCertifiateRequest();

            //
            // Only check if server hello done was received
            GetServerHelloDone();

            SendCertifiate();
            SendClientKeyExchange();
            SendCertifiateVerify();
            SendChangeCipherSpec();

            
            // change cipher spec in own record layer
            recordLayer.ChangeWriteCipherSpec(secParams);
            SendFinished();

            protocol.ChangeCipherSpecHandler -= FatalCCS;
            protocol.HandshakeHandler -= ReadHandshakeAndCache;

            protocol.ChangeCipherSpecHandler += ExpectedChangeCipherSpec;
            protocol.HandshakeHandler += FatalHandshake;

            protocol.Read();

            // back to handshake, now connection is encrypted
            protocol.ChangeCipherSpecHandler -= ExpectedChangeCipherSpec;
            protocol.ChangeCipherSpecHandler += FatalCCS;

            protocol.HandshakeHandler -= FatalHandshake;
            protocol.HandshakeHandler += ReadHandshakeAndCache;
            
            // start reading process
            protocol.Read();
            GetFinished();

            protocol.ApplicationDataHandler -= FatalApplicationData;
            protocol.ApplicationDataHandler += UpdateAppDataBuffer;
            //ExchangeApplicationData();
        }

        private void ExpectedChangeCipherSpec(ChangeCipherSpec changeCipherSpec)
        {
            recordLayer.ChangeReadCipherSpec(secParams);
        }

        private void ReadHandshakeAndCache(Handshake message, byte[] rawBytes)
        {
            handshakeStack.Push(rawBytes, message.MsgType, HandshakeStack.TransmitType.Received);
            currentHandshakeMessage = message;
        }

        private void UpdateAppDataBuffer(byte[] buf, int offset, int len)
        {
            if (appDataBuffer == null)
            {
                appDataBuffer = new byte[len];
                Buffer.BlockCopy(buf, offset, appDataBuffer, 0, len);
                appDataOffset = 0;
                appDataLength = len;
            }
            else
            {
                if (len > appDataBuffer.Length)
                {

                }
            }
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
            if (currentHandshakeMessage.MsgType != HandshakeType.Finished) throw new Exception("expected finished but something else received");

            PseudoRandomFunction prf = new PseudoRandomFunction();


            MD5 md5 = MD5.Create();
            SHA1 sha1 = SHA1.Create();

            var stack = handshakeStack.GetStack();

            for (int i = 0; i < stack.Length - 2; i++)
            {
                //if (stack[i].HandshakeMsgType == HandshakeType.Finished && stack[i].Transmit == HandshakeStack.TransmitType.Received) continue;
                md5.TransformBlock(stack[i].TransmittedBytes, 0, stack[i].TransmittedBytes.Length, null, 0);
                sha1.TransformBlock(stack[i].TransmittedBytes, 0, stack[i].TransmittedBytes.Length, null, 0);
            }

            md5.TransformFinalBlock(stack[stack.Length - 2].TransmittedBytes, 0, stack[stack.Length - 2].TransmittedBytes.Length);
            sha1.TransformFinalBlock(stack[stack.Length - 2].TransmittedBytes, 0, stack[stack.Length - 2].TransmittedBytes.Length);

            byte[] hashes = BufferTools.Join(md5.Hash, sha1.Hash);

            byte[] finishedContent = prf.Prf(secParams.MasterSecret, "server finished", hashes, 12);

            Finished f = (Finished)currentHandshakeMessage;
            //string a = ""; 
        }

        private void SendFinished()
        {
            PseudoRandomFunction prf = new PseudoRandomFunction();
            

            MD5 md5 = MD5.Create();
            SHA1 sha1 = SHA1.Create();

            var stack = handshakeStack.GetStack();

            for (int i = 0; i < stack.Length - 1; i++)
            {
                md5.TransformBlock(stack[i].TransmittedBytes, 0, stack[i].TransmittedBytes.Length, null, 0);
                sha1.TransformBlock(stack[i].TransmittedBytes, 0, stack[i].TransmittedBytes.Length, null, 0);
            }

            md5.TransformFinalBlock(stack[stack.Length - 1].TransmittedBytes, 0, stack[stack.Length - 1].TransmittedBytes.Length);
            sha1.TransformFinalBlock(stack[stack.Length - 1].TransmittedBytes, 0, stack[stack.Length - 1].TransmittedBytes.Length);

            byte[] hashes = BufferTools.Join(md5.Hash, sha1.Hash);

            byte[] finishedContent = prf.Prf(secParams.MasterSecret, "client finished", hashes, 12);

            Finished f = new Finished(finishedContent);

            WriteAndCacheMessage(f);
        }

        private void SendChangeCipherSpec()
        {
            protocol.Write(new ChangeCipherSpec() { CCSType = ChangeCipherSpecType.ChangeCipherSpec });
        }

        private void SendCertifiateVerify()
        {
            //process sending cert verify
        }

        private void SendClientKeyExchange()
        {
            ClientKeyExchange kkx = new ClientKeyExchange();
            byte[] premaster = GeneratePremasterSecret();
            byte[] encrypted = EncryptPremasterSecret(premaster);

            kkx.ExchangeKeys = encrypted;

            WriteAndCacheMessage(kkx);

            SecretGenerator secGenerator = new SecretGenerator();
            SecretGenerator.SecParams11Seed seed = new SecretGenerator.SecParams11Seed();

            seed.ClientRandom = allMessages.ClientHello.Random;
            seed.CompressionMethod = allMessages.ServerHello.CompressionMethod;
            seed.HostType = Protocol.RecordProtocol.ConnectionEnd.Client;
            seed.Premaster = premaster;
            seed.RecordCryptoType = CryptoSuites.Get(allMessages.ServerHello.CipherSuite).RecordCryptoType;
            seed.ServerRandom = allMessages.ServerHello.Random;

            secParams = secGenerator.GenerateSecParams11(seed);


        }

        private byte[] EncryptPremasterSecret(byte[] premaster)
        {
            RSACryptoServiceProvider pubKey = (RSACryptoServiceProvider)allMessages.ServerCertificate.ANS1Certificates[0].PublicKey.Key;
            byte[] encrypted = pubKey.Encrypt(premaster, false);

            return encrypted;
        }

        private byte[] GeneratePremasterSecret()
        {
            Random r = new Random();
            byte[] premaster = new byte[48];

            for (int i = 2; i < 48; i++)
            {
                premaster[i] = (byte)r.Next();
            }
            premaster[0] = 3;
            premaster[1] = 2;

            return premaster;
        }

        private void SendCertifiate()
        {
            //send certificate process
        }

        private void GetServerHelloDone()
        {
            if (currentHandshakeMessage.MsgType != HandshakeType.ServerHelloDone)
            {
                throw new Exception("Expected server hello done ");
            }

            currentHandshakeMessage = null;

            //expect something after hello done ? NO, now client sends data
            // protocol.Read();
        }

        private void GetCertifiateRequest()
        {
            if (currentHandshakeMessage.MsgType == HandshakeType.CertificateRequest)
            {
                //do some processing with certificate request
                throw new NotImplementedException("certificate request not implemented");
                protocol.Read();
            }
        }

        private void GetServerKeyExchange()
        {
            if (currentHandshakeMessage.MsgType == HandshakeType.ClientKeyExchange)
            {
                //do something with this message.
                
                throw new NotImplementedException("Server key exchange not implemented");
                // always expect server hello done OR next conditional message
                protocol.Read();   
            }
        }

        private void GetCertifiate()
        {
            if (currentHandshakeMessage.MsgType != HandshakeType.Certificate)
                throw new Exception("expected certificate");

            allMessages.ServerCertificate = (Certificate)currentHandshakeMessage;

            // expecte somethind AFTER certificate ? Yes, always server hello done OR conditional messages
            protocol.Read();
        }

        private void GetServerHello()
        {
            if (currentHandshakeMessage.MsgType != HandshakeType.ServerHello) throw new Exception("expected server hello");
            allMessages.ServerHello = (ServerHello)currentHandshakeMessage;

            //Expect something after server hello  ? Yes certificate or serverhellodone
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

            allMessages.ClientHello = hello;

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
            protocol.Read();
            //recordLayer.Write(buffer, offset, count, Protocol.RecordProtocol.ContentType.ApplicationData);
        }

        public override int ReadApplicationData(byte[] buffer, int offset, int count)
        {
            return -1;
            if (appDataOffset < appDataLength)
            {

            }
            else
            {
                protocol.Read();
            }
        }
    }
}
