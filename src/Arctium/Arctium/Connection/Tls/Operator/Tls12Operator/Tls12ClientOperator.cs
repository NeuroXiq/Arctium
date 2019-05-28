using Arctium.Connection.Tls.Buffers;
using Arctium.Connection.Tls.Configuration;
using Arctium.Connection.Tls.CryptoConfiguration;
using Arctium.Connection.Tls.CryptoFunctions;
using Arctium.Connection.Tls.Exceptions;
using Arctium.Connection.Tls.Protocol;
using Arctium.Connection.Tls.Protocol.AlertProtocol;
using Arctium.Connection.Tls.Protocol.BinaryOps.Builder;
using Arctium.Connection.Tls.Protocol.BinaryOps.Formatter;
using Arctium.Connection.Tls.Protocol.ChangeCipherSpecProtocol;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using Arctium.Connection.Tls.Protocol.RecordProtocol;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace Arctium.Connection.Tls.Operator.Tls12Operator
{
    class Tls12ClientOperator : TlsProtocolOperator
    {

        RecordLayer12 recordLayer;
        Tls12ClientConfig config;

        // this field is very important. Is updated by all Get..() and Send...() methods
        // and holds all sended and received messages. Is also contains readers and writers of the
        // handshake and appdata protocols, and contains RecordLayer12 instance.
        // 
        Context currentContext;
        Handshake currentMessageToProcess;
        ExtensionsHandler extensionHandler;
        ClientKeyExchangeService currentKeyExchangeService;

        bool canExchangeAppData;

        public Tls12ClientOperator(Tls12ClientConfig config, Stream innerStream)
        {
            recordLayer = RecordLayer12.Initialize(innerStream);
            this.config = config;
            canExchangeAppData = false;
        }

        public override void CloseNotify()
        {
            throw new NotImplementedException();
        }

        public override int ReadApplicationData(byte[] buffer, int offset, int count)
        {
            if (!canExchangeAppData) throw new InvalidOperationException("Cannot read application data on this state of Thls12ClientOperator");
            currentContext.appDataIO.PrepareToRead();

            return currentContext.appDataIO.Read(buffer, offset, count);
        }

        public override void WriteApplicationData(byte[] buffer, int offset, int count)
        {
            if (!canExchangeAppData) throw new InvalidOperationException("Cannot send application data on this state of Tls12ClientOperator");
            currentContext.appDataIO.Write(buffer, offset, count);
        }

        public void OpenSession()
        {
            currentContext = new Context(recordLayer);
            extensionHandler = new ExtensionsHandler();
            currentKeyExchangeService = new ClientKeyExchangeService(currentContext);

            try
            {
                SendClientHello();
                currentMessageToProcess = currentContext.handshakeIO.Read();
                GetServerHello();
                ProcessHandshakeAfterServerHello();

                OnSuccessHandshake();
            }
            catch (FatalAlertException e)
            {
                ActionBeforeThrowFatalAlertException(e);
                throw e;
            }
            catch (ReceivedWarningAlertException e)
            {
                
                ActionBeforeThrowReceivedWarningAlertException(e);
                throw e;
            }
            catch (ReceivedFatalAlertException e)
            {
                ActionBeforeThrowReceivedFatalAlertException(e);
                throw e;
            }
            catch (Exception e)
            {
                ActionBeforeThrowInternalException(e);
                throw e;
            }
        }

        private void ActionBeforeThrowInternalException(Exception e)
        {
            canExchangeAppData = false;
            
            //trying to send that internal error occur
            //if cannot send because some exception during transmission just ignore this
            try
            {
                byte[] internalErrorAlert = AlertFormatter.FormatAlert(AlertDescription.InternalError, AlertLevel.Fatal);
                recordLayer.Write(internalErrorAlert, 0, internalErrorAlert.Length, ContentType.Alert);
            }
            catch (Exception ignoreException)
            {

            }
        }

        private void ActionBeforeThrowReceivedFatalAlertException(ReceivedFatalAlertException e)
        {
            canExchangeAppData = false;
        }

        private void ActionBeforeThrowReceivedWarningAlertException(ReceivedWarningAlertException e)
        {
            canExchangeAppData = false;
        }

        private void ActionBeforeThrowFatalAlertException(FatalAlertException e)
        {
            canExchangeAppData = false;
            //
            // send alert to server

            byte[] alertBytes = AlertFormatter.FormatAlert((AlertDescription)e.AlertDescriptionNumber, AlertLevel.Fatal);

            try
            {
                recordLayer.Write(alertBytes, 0, alertBytes.Length, ContentType.Alert);
            }
            catch (Exception ignoreException)
            {
                // ignore any errors during alert transmission,
                // this method is last operation before throwing exception
            }
        }

        private void OnSuccessHandshake()
        {
            canExchangeAppData = true;
        }

        //
        // All steps are conditional and base on current 'Context' instance (currentContext field) and 'currentMessageToProcess'
        // Assumption is made that message is already readed and holded by 'currentMessageToProcess'
        // and if when readed message before method call, conditional server messages can be 
        // processed more easily
        // 'Conditional messages' means Handshake messages which can be sended by server but server can ignore them (like certificate request)

        private void ProcessHandshakeAfterServerHello()
        {
            GetCertificate();
            GetServerKeyExchange();
            GetCertificateRequest();
            GetServerHelloDone();

            SendCertificate();
            SendClientKeyExchange();
            SendCertificateVerify();

            UpdateSecrets();
            SendChangeCipherSpes();
            ChangeWriteCipherSpec();
            SendFinished();

            ReadChangeCipherSpec();
            ChangeReadCipherSpec();

            //read after record layer changed cipher spec
            currentMessageToProcess = currentContext.handshakeIO.Read();
            ReadFinished();            
        }

        private void ChangeReadCipherSpec()
        {
            RecordCryptoType recordCrypto = CryptoSuites.Get(currentContext.allHandshakeMessages.ServerHello.CipherSuite).RecordCryptoType;

            RecordLayer12Params readParams = new RecordLayer12Params();
            readParams.BulkKey = currentContext.secrets.ServerWriteKey;
            readParams.MacKey = currentContext.secrets.ServerWriteMacKey;
            readParams.RecordCryptoType = recordCrypto;

            recordLayer.ChangeReadCipherSpec(readParams);
        }

        private void ReadFinished()
        {
            ThrowIfUnexpectedHandshakeMessage(HandshakeType.Finished, currentMessageToProcess.MsgType);
            currentContext.allHandshakeMessages.ServerFinished = (Finished)currentMessageToProcess;

            byte[] expectedServerVerifyData = ComputeExpectedVerifyDataFromServer();
            byte[] receivedVerifyData = currentContext.allHandshakeMessages.ServerFinished.VerifyData;

            if (expectedServerVerifyData.Length != receivedVerifyData.Length)
                throw new FatalAlertException("Tls12ClientOperator", "On verify data from server validation", (int)AlertDescription.DecryptError, "expected verify data length is other than received from server");

            for (int i = 0; i < expectedServerVerifyData.Length; i++)
            {
                if (expectedServerVerifyData[i] != receivedVerifyData[i])
                {
                    throw new FatalAlertException("Tls12ClientOperator", "On comparing expected verify data from server", (int)AlertDescription.DecryptError, "Vefiry data received from server are different than expected computer locally");
                }
            }
        }

        private byte[] ComputeExpectedVerifyDataFromServer()
        {
            HandshakeType ignore = HandshakeType.CertificateVerify;
            HandshakeIO.HandshakeMessageData[] allMsgs = currentContext.handshakeIO.HandshakeTransmissionCache;

            SHA256 sha256 = SHA256.Create();

            foreach (var msg in allMsgs)
            {
                if (ignore == msg.Type) continue;
                if (msg.Type == HandshakeType.Finished)
                {
                    sha256.TransformFinalBlock(msg.RawBytes, 0, msg.RawBytes.Length);
                    break;
                }
                sha256.TransformBlock(msg.RawBytes, 0, msg.RawBytes.Length, null, 0);
            }
            byte[] master = currentContext.secrets.MasterSecret;

            byte[] computedAsServer = PRF.Prf12(master, "server finished", sha256.Hash, 12);

            return computedAsServer;
        }

        private void ReadChangeCipherSpec()
        {
            //reading directly from the record layer

            byte[] ccsExptectedByte = new byte[0x4800];
            ContentType readedContetType;
            int readedBytes = recordLayer.ReadFragment(ccsExptectedByte, 0, out readedContetType);
            
            if (readedContetType != ContentType.ChangeCipherSpec)
            {
                if (readedContetType == ContentType.Alert)
                {
                    Alert alert = AlertBuilder.FromBytes(ccsExptectedByte, 0, readedBytes);
                    string where = "tls12clientoperator";
                    string when = "on reading change cipher spec";
                    string description = "expected to read change cipher spec byte but received alert message";

                    if (alert.Level == AlertLevel.Fatal)
                        throw new ReceivedFatalAlertException((int)alert.Description, where, when, description);
                    else throw new ReceivedWarningAlertException((int)alert.Description, where, when, description);

                }
                throw new FatalAlertException("Tls12ClientOperator", "On reading Change cipher spec",
                (int)AlertDescription.UnexpectedMessage,
                "tried to read 1 byte of the change cipher spec protocol but readed something else");
            }

            //ok
        }

        private void SendFinished()
        {
            byte[] verifyData = ComputeVerifyDataToSend();
            Finished finished = new Finished(verifyData);

            currentContext.handshakeIO.Write(finished);
        }

        private byte[] ComputeVerifyDataToSend()
        {
            HandshakeIO.HandshakeMessageData[] allExchangedMsgs = currentContext.handshakeIO.HandshakeTransmissionCache;
            HandshakeType toIgnoreMsg = HandshakeType.CertificateVerify;

            SHA256 sha256 = SHA256.Create();

            foreach (var msgData in allExchangedMsgs)
            {
                if (toIgnoreMsg == msgData.Type) continue;
                if (msgData.Type == HandshakeType.Finished) break;
                sha256.TransformBlock(msgData.RawBytes, 0, msgData.RawBytes.Length, null, 0);
            }

            sha256.TransformFinalBlock(new byte[0], 0, 0);

            byte[] master = currentContext.secrets.MasterSecret;
            //byte[] clientRandom = currentContext.allHandshakeMessages.ClientHello.Random;
            //byte[] serverRandom = currentContext.allHandshakeMessages.ServerHello.Random;
            //byte[] seed = BufferTools.Join(clientRandom, serverRandom);

            byte[] seed = sha256.Hash;

            byte[] verifyData = PRF.Prf12(master, "client finished", seed, 12);

            return verifyData;
        }

        private void SendChangeCipherSpes()
        {
            //ccs is so simple that there is no need to create some formatter.
            //this is just 1 byte
            byte[] ccsBytes = new byte[] { (byte)ChangeCipherSpecType.ChangeCipherSpec };

            // write directly to recordlayer
            // note: other messages are writed by some 'writers' like 'HandshakeIO'

            //and how writing directly to the record layer looks like:
            recordLayer.Write(ccsBytes, 0, ccsBytes.Length, ContentType.ChangeCipherSpec);
        }

        private void ChangeWriteCipherSpec()
        {
            //translate fixed-number cipher suite e.g. TLS_RSA_WITH_AES_128_CBC_SHA
            //to object notation
            CryptoSuite selectedSuite = CryptoSuites.Get(currentContext.allHandshakeMessages.ServerHello.CipherSuite);

            // selected suite contains informations about symmetric encrypition (key length, cipher type e.g AES )
            // and also about key exchange algorithm. Record layer need only data associated with record encrypition (symmetric encryption)
            // This object contains filed repsenting symmetric encryption:

            RecordCryptoType recordEncryptionType = selectedSuite.RecordCryptoType;

            //assmue that secres are updated in current context, assign appropriate values
            RecordLayer12Params writeParams = new RecordLayer12Params();
            writeParams.BulkKey = currentContext.secrets.ClientWriteKey;
            writeParams.MacKey = currentContext.secrets.ClientWriteMacKey;

            //explicit define symmetric encryption algorithms:
            writeParams.RecordCryptoType = recordEncryptionType;

            // change write cipher spec on the record layer,
            // after this step, all (only) write operations are encrypted and HMAC'ed
            // recordLayer in injected to 'Context.HandshakeIO' and 'Context.AppDataIO'
            // and changing recordLayer state have infulence in this structurs
            
            recordLayer.ChangeWriteCipherSpec(writeParams);
        }

        private void UpdateSecrets()
        {
            RecordCryptoType cryptoType = CryptoSuites.Get(currentContext.allHandshakeMessages.ServerHello.CipherSuite).RecordCryptoType;
            byte[] currentPremaster = currentKeyExchangeService.Premaster;
            byte[] clientRandom = currentContext.allHandshakeMessages.ClientHello.Random;
            byte[] serverRandom = currentContext.allHandshakeMessages.ServerHello.Random;

            Tls12Secrets newCurrentSecrets = SecretGenerator.GenerateTls12Secrets(cryptoType, currentPremaster, clientRandom, serverRandom);

            currentContext.secrets = newCurrentSecrets;
        }

        private void SendCertificateVerify()
        {
            if (NeedToSendCertificateVerify())
            {
                //send certificate verify
            }
        }

        private bool NeedToSendCertificateVerify()
        {
            return false;
        }

        private void SendClientKeyExchange()
        {
            ClientKeyExchange clientKeyExchange = currentKeyExchangeService.CreateNewClientKeyExchangeMessage();
            currentContext.handshakeIO.Write(clientKeyExchange);
        }

        private void SendCertificate()
        {
            if (NeedToSendCertificate())
            {
                // send certificate
            }
        }

        private bool NeedToSendCertificate()
        {
            return false;
        }

        private void GetServerHelloDone()
        {
            ThrowIfUnexpectedHandshakeMessage(HandshakeType.ServerHelloDone, currentMessageToProcess.MsgType);
            currentContext.allHandshakeMessages.ServerHelloDone = (ServerHelloDone)currentMessageToProcess;
        }

        private void GetCertificateRequest()
        {
            if (currentMessageToProcess.MsgType == HandshakeType.CertificateRequest)
            {
                currentContext.allHandshakeMessages.CertificateRequset = (CertificateRequest)currentMessageToProcess;

                currentMessageToProcess = currentContext.handshakeIO.Read();
            }
        }

        private void ProcessCertifiateRequest(CertificateRequest msg)
        {
            throw new NotImplementedException();
        }

        private void GetServerKeyExchange()
        {
            if (currentKeyExchangeService.ExpectToReadServerKeyExchange())
            {
                ThrowIfUnexpectedHandshakeMessage(HandshakeType.ServerKeyExchange, currentMessageToProcess.MsgType);
                currentContext.allHandshakeMessages.ServerKeyExchage = (ServerKeyExchange)currentMessageToProcess;

                currentMessageToProcess = currentContext.handshakeIO.Read();
            }

            // not expected to read ServerKeyExchange,
            // leave currentMessageToProcess to another processing method
        }

        private bool ExpectToReadServerKeyExchange()
        {
            return false;
        }

        private void GetCertificate()
        {
            ThrowIfUnexpectedHandshakeMessage(HandshakeType.Certificate, currentMessageToProcess.MsgType);
            currentContext.allHandshakeMessages.ServerCertificate = (Certificate)currentMessageToProcess;

            currentMessageToProcess = currentContext.handshakeIO.Read();
        }

        //
        // Test session resumption code
        //
        public void OpenSession(Tls12Session cachedSession)
        {
            ClientHello clientHello = new ClientHello();

            clientHello.CipherSuites = config.EnableCipherSuites;
            bool found = false;

            foreach (CipherSuite s in config.EnableCipherSuites)
            {
                if (s == cachedSession.SelectedCipherSuite) found = true;
            }
            if (!found) throw new ArgumentException("Invalid paramters in config and TLS12Session. Config do not contain cipher suite which cachedSession contains");

        }


        private void GetServerHello()
        {
            ThrowIfUnexpectedHandshakeMessage(HandshakeType.ServerHello, currentMessageToProcess.MsgType);

            currentContext.allHandshakeMessages.ServerHello = (ServerHello)currentMessageToProcess;
            currentMessageToProcess = currentContext.handshakeIO.Read();
        }

        

        private void SendClientHello()
        {
            ClientHello clientHello = new ClientHello();

            clientHello.CipherSuites = config.EnableCipherSuites; ;
            clientHello.ClientVersion = new Protocol.ProtocolVersion(3, 3);
            clientHello.CompressionMethods = new CompressionMethod[] { CompressionMethod.NULL };
            clientHello.Extensions = extensionHandler.BuildClientHelloExtensions(config.Extensions);
            clientHello.Random = GenerateRandom(32);
            clientHello.SessionID = GenerateRandom(32);

            currentContext.handshakeIO.Write(clientHello);
            currentContext.allHandshakeMessages.ClientHello = clientHello;
        }

        private byte[] GenerateRandom(int randomLength)
        {
            byte[] buffer = new byte[randomLength];
            Random r = new Random();
            r.NextBytes(buffer);

            return buffer;
        }



        private void ThrowIfUnexpectedHandshakeMessage(HandshakeType expectedType, HandshakeType currentType)
        {
            if (currentType != expectedType)
            {
                string description = string.Format("Expected to read handshake type: {0} but readed : {1}", expectedType, currentType);
                throw new FatalAlertException(
                    "Tls12ClientOperator",
                    "After reading handshake message",
                    (int)AlertDescription.UnexpectedMessage,
                    description);
            }
        }
    }
}
