using Arctium.Connection.Tls.Configuration;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12;
using System.IO;
using System;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using System.Security.Cryptography.X509Certificates;
using Arctium.Connection.Tls.Protocol;
using Arctium.Connection.Tls.CryptoFunctions;
using System.Security.Cryptography;
using Arctium.Connection.Tls.Protocol.AlertProtocol;
using Arctium.Connection.Tls.Protocol.RecordProtocol;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer;
using Arctium.Connection.Tls.Protocol.BinaryOps.Formatter;
using Arctium.Connection.Tls.Protocol.ChangeCipherSpecProtocol;
using System.Collections.Generic;
using Arctium.Connection.Tls.Exceptions;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions;
using Arctium.Connection.Tls.Configuration.TlsExtensions;

namespace Arctium.Connection.Tls.Operator.Tls12Operator
{

    class Tls12ServerOperator : TlsProtocolOperator
    {
        Tls12ServerConfig config;
        RecordLayer12 recordLayer;
        ExtensionsHandler extensionsHandler;
        Context currentContext;

        bool isSessionOpened;
        bool closeNotifySended;
        AppDataIO appDataIO;
            
        //TODO end 

        public Tls12ServerOperator(Tls12ServerConfig config, Stream innerStream)
        {
            this.config = config;
            isSessionOpened = false;
            closeNotifySended = false;

            //create initial state of the record layer
            //this initialization means that record layer algo is TLS_NULL_WITH_NULL_NULL
            //plain data exchange at this moment

            this.recordLayer = RecordLayer12.Initialize(innerStream);
            extensionsHandler = new ExtensionsHandler();
        }

        //
        // public methods
        //

        ///<summary>Reads application data application data to the specified</summary>
        ///<param name="buffer">Buffer to write application data bytes</param>
        ///<param name="count">Bytes length to write</param>
        ///<param name="offset">Offset in buffer to write data</param>
        public override int ReadApplicationData(byte[] buffer, int offset, int count)
        {
            if (!isSessionOpened || closeNotifySended) throw new InvalidOperationException("Cannot read applicaiton data because session is not opened is closed");

            appDataIO.PrepareToRead();

            if (appDataIO.CurrentContentType != ContentType.ApplicationData)
                throw new Exception("Internal error TLS 1.2. Received other content type than Application data. Current implementation do not handle this state");

            return appDataIO.Read(buffer, offset, count);
        }

        ///<summary>Writes application data from specified buffer and sends to client</summary>
        public override void WriteApplicationData(byte[] buffer, int offset, int count)
        {
            if (!isSessionOpened || closeNotifySended) throw new InvalidOperationException("Cannot write applicaiton data because session is not opened or is closed");

            appDataIO.Write(buffer, offset, count);
        }

        public override void CloseNotify()
        {
            if (!isSessionOpened)
                throw new InvalidOperationException("Cannot send close notify because session is not opened");
            if (closeNotifySended) throw new InvalidOperationException("Cannot send close notify because it was sended");

            byte[] closeBytes = AlertFormatter.FormatAlert(AlertDescription.CloseNotify, AlertLevel.Warning);
            recordLayer.Write(closeBytes,0,closeBytes.Length, ContentType.Alert);

            closeNotifySended = true;
        }

        public HandshakeMessages OpenSession()
        {
            if (isSessionOpened) throw new InvalidOperationException("Cannot open session because is already opened");
            if (closeNotifySended) throw new InvalidOperationException("Cannot open session because close notify was sended.");

            currentContext = new Context(recordLayer);

            try
            {
                GetClientHello();
                ProcessSessionOpenAfterClientHello();

                isSessionOpened = true;
            }
            catch (FatalAlertException e)
            {
                ActionOnFatalException();
                SendFatalAlert((AlertDescription)e.AlertDescriptionNumber);
                throw e;
            }
            catch (Exception e)
            {
                //unrecognized exception, internal error
                SendFatalAlert(AlertDescription.InternalError);
                ActionOnFatalException();
                throw e;
            }

            return currentContext.allHandshakeMessages;
        }

        //
        // End public methods
        //

        private void ActionOnFatalException()
        {
            return;
        }

        private void SendFatalAlert(AlertDescription alertDescription)
        {
            //consider that exception can occur because connection was lost.
            //then just ignore this new exception (or any other)
            try
            {
                byte[] alertBytes = AlertFormatter.FormatAlert(alertDescription, AlertLevel.Fatal);
                recordLayer.Write(alertBytes, 0, alertBytes.Length, ContentType.Alert);
            }
            catch (Exception e)
            {
                //at this point ignore any exception
                //connection must be closed after exit this block, fatal alert is the last transmission between client and server
            }
        }

        private void ProcessSessionOpenAfterClientHello()
        {
            SendServerHello();
            SendCertificate();
            SendServerKeyExchange();
            SendCertificateRequest();
            SendServerHelloDone();

            GetCertificate();
            GetClientKeyExchange();
            GetCertificateVerify();

            //before change cipher, compute secrets in context
            UpdateSecrets();

            GetChangeCipherSpec();
            GetFinished();

            SendChangeCipherSpec();

            SendFinished();

            //after all steps, prepare internal environment to exchange app data
            ActionOnHandshakeEndSuccess();
        }

        private void ActionOnHandshakeEndSuccess()
        {
            appDataIO = new AppDataIO(recordLayer);
            isSessionOpened = true;
        }

        private void SendFinished()
        {
            byte[] finishedData = ComputeCurrentFinished("server finished");
            Finished finished = new Finished(finishedData);

            currentContext.handshakeIO.Write(finished);
        }

        private void SendChangeCipherSpec()
        {
            byte[] changeCipherSpecBytes = new byte[] { (byte)(ChangeCipherSpecType.ChangeCipherSpec) };
            recordLayer.Write(changeCipherSpecBytes, 0, 1, ContentType.ChangeCipherSpec);

            RecordLayer12Params writeParams = new RecordLayer12Params();
            writeParams.BulkKey = currentContext.secrets.ServerWriteKey;
            writeParams.MacKey = currentContext.secrets.ServerWriteMacKey;
            writeParams.RecordCryptoType = CryptoSuites.Get(currentContext.allHandshakeMessages.ServerHello.CipherSuite).RecordCryptoType;

            recordLayer.ChangeWriteCipherSpec(writeParams);
        }

        private void GetFinished()
        {
            //compute client finished before reading it
            byte[] expectedHash = ComputeCurrentFinished("client finished");

            //now read finished (not included in computations above)
            Handshake message = currentContext.handshakeIO.Read();
            ThrowIfUnexpedtedHandshakeMessage(HandshakeType.Finished, message.MsgType);

            Finished finished = (Finished)message;
            
            byte[] receivedHash = finished.VerifyData;

            for (int i = 0; i < expectedHash.Length; i++)
            {
                if (expectedHash[i] != receivedHash[i])
                {
                    ThrowInvalidFinishedContentAlertException();

                    
                }
            }
        }

        private void ThrowInvalidFinishedContentAlertException()
        {
            string when = "On processing finished message";
            string where = "Tls12ServerOperator";
            string description = "Finished message contains invalid data";

            throw new FatalAlertException(where,when,(int)AlertDescription.DecryptError, description);
        }

        private byte[] ComputeCurrentFinished(string label)
        {
            HandshakeIO.HandshakeMessageData[] allMsgBytes = currentContext.handshakeIO.HandshakeTransmissionCache;
            List<byte[]> toComputeFinished = new List<byte[]>();

            foreach (var msgData in allMsgBytes)
            {
                if (msgData.Type != HandshakeType.HelloRequest && msgData.Type != HandshakeType.CertificateVerify)
                    toComputeFinished.Add(msgData.RawBytes);
            }

            SHA256 sha256 = SHA256.Create();

            for (int i = 0; i < toComputeFinished.Count - 1; i++)
            {
                sha256.TransformBlock(toComputeFinished[i], 0, toComputeFinished[i].Length, null, 0);
            }
            sha256.TransformFinalBlock(toComputeFinished[toComputeFinished.Count - 1], 0, toComputeFinished[toComputeFinished.Count - 1].Length);

            byte[] computedHash = sha256.Hash;

            byte[] computedFinished = PRF.Prf12(currentContext.secrets.MasterSecret, label, computedHash, 12);

            return computedFinished;
        }

        private void GetChangeCipherSpec()
        {
            //record layer expect that buffer will be at least 2^14 bytes,
            //CCS message always contains only 1 bytes and fragment length must be 1.
            //If OutOfRange exception is throw, it means that something is wrong but this can be ignored.
            //Not receiving at this point ccs is fatal
            try
            {
                byte[] ccsBytes = new byte[1];
                ContentType contentType;
                recordLayer.ReadFragment(ccsBytes, 0, out contentType);

                if (contentType != ContentType.ChangeCipherSpec)
                    throw new FatalAlertException("","",(int)AlertDescription.UnexpectedMessage, "Expected to receive change cipher spec");
            }
            catch (Exception e)
            {
                throw new FatalAlertException("","",(int)AlertDescription.UnexpectedMessage, "Expected to receive change cipher spec");
            }

            RecordLayer12Params readParams = new RecordLayer12Params();
            readParams.BulkKey = currentContext.secrets.ClientWriteKey;
            readParams.MacKey = currentContext.secrets.ClientWriteMacKey;
            readParams.RecordCryptoType = CryptoSuites.Get(currentContext.allHandshakeMessages.ServerHello.CipherSuite).RecordCryptoType;

            recordLayer.ChangeReadCipherSpec(readParams);
        }

        private void GetCertificateVerify()
        {
            return;
        }

        private void GetClientKeyExchange()
        {
            Handshake message = currentContext.handshakeIO.Read();
            ThrowIfUnexpedtedHandshakeMessage(HandshakeType.ClientKeyExchange, message.MsgType);

            currentContext.allHandshakeMessages.ClientKeyExchange = (ClientKeyExchange)message;
        }

        private void GetCertificate()
        {
            return;
        }

        private void SendServerHelloDone()
        {
            ServerHelloDone serverHelloDone = new ServerHelloDone();

            currentContext.handshakeIO.Write(serverHelloDone);
            currentContext.allHandshakeMessages.ServerHelloDone = serverHelloDone;
        }

        private void SendCertificateRequest()
        {
            return;
        }

        private void SendServerKeyExchange()
        {
            return;
        }

        private void SendCertificate()
        {
            Certificate certificate = new Certificate(config.Certificates);

            currentContext.handshakeIO.Write(certificate);
            currentContext.allHandshakeMessages.ServerCertificate = certificate;
        }

        private void SendServerHello()
        {
            ServerHello serverHello = new ServerHello();
            CipherSuite selectedSuite = NegotiateCipherSuite();

            serverHello.CipherSuite = selectedSuite;
            serverHello.CompressionMethod = CompressionMethod.NULL;
            serverHello.ProtocolVersion = new ProtocolVersion(3, 3);
            serverHello.Random = GenerateRandom();
            serverHello.SessionID = GenerateSessionID();
            serverHello.Extensions = BuildServerHelloExtensions();

            currentContext.handshakeIO.Write(serverHello);
            currentContext.allHandshakeMessages.ServerHello = serverHello;
        }

        private HandshakeExtension[] BuildServerHelloExtensions()
        {
            TlsHandshakeExtension[] configExtensions  = config.HandshakeExtensions;
            HandshakeExtension[] extensionsFromClient = currentContext.allHandshakeMessages.ClientHello.Extensions;

            HandshakeExtension[] serverExtensions = extensionsHandler.BuildAllHandshakeExtensionsOnServer(extensionsFromClient, configExtensions);

            return serverExtensions;
        }

        private void ThrowIfInvalidClientExtensions()
        {
            return;
        }

        private byte[] GenerateSessionID()
        {
            Random r = new Random();
            byte[] random = new byte[32];
            r.NextBytes(random);

            return random;
        }

        private byte[] GenerateRandom()
        {
            Random r = new Random();
            byte[] random = new byte[32];
            r.NextBytes(random);

            return random;
        }

        private void GetClientHello()
        {
            Handshake msg = currentContext.handshakeIO.Read();

            ThrowIfUnexpedtedHandshakeMessage(HandshakeType.ClientHello, msg.MsgType);

            currentContext.allHandshakeMessages.ClientHello = (ClientHello)msg;
        }

        private void ThrowIfUnexpedtedHandshakeMessage(HandshakeType expected, HandshakeType received)
        {
            if (expected != received)
            {
                string description = string.Format("Unexpected handshake message: Expected: {0} Received: {1}", expected, received);
                throw new FatalAlertException("Tls12ServerOperator","After read handshake message",(int)AlertDescription.UnexpectedMessage, description);
            }
        }

        private CipherSuite NegotiateCipherSuite()
        {
            CipherSuite[] clientSuites = currentContext.allHandshakeMessages.ClientHello.CipherSuites;
            CipherSuite[] availableSuites = config.EnableCipherSuites;

            for (int i = 0; i < clientSuites.Length; i++)
            {
                for (int j = 0; j < availableSuites.Length; j++)
                {
                    if (clientSuites[i] == availableSuites[j])
                    {
                        return clientSuites[i];
                    }
                }
            }

            throw new FatalAlertException("Tls12ServerOperator", "On processing client hello", (int)AlertDescription.HandshakeFailure, 
                "Any client cipher suite do not match currently available server cipher suite");
        }

        private void UpdateSecrets()
        {
            byte[] premaster = GetPremaster();
            byte[] clientRandom = currentContext.allHandshakeMessages.ClientHello.Random;
            byte[] serverRandom = currentContext.allHandshakeMessages.ServerHello.Random;
            RecordCryptoType recordCryptoType = CryptoSuites.Get(currentContext.allHandshakeMessages.ServerHello.CipherSuite).RecordCryptoType;
            currentContext.secrets = SecretGenerator.GenerateTls12Secrets(recordCryptoType, premaster, clientRandom, serverRandom);
        }

        private byte[] GetPremaster()
        {
            RSA rsa = config.Certificates[0].GetRSAPrivateKey();
            return rsa.Decrypt(currentContext.allHandshakeMessages.ClientKeyExchange.ExchangeKeys, RSAEncryptionPadding.Pkcs1);
        }

    }
}
