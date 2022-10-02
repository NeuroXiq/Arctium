using Arctium.Shared;
using Arctium.Shared.Helpers;
using Arctium.Shared.Other;
using Arctium.Standards.Connection.Tls.Tls13.API;
using Arctium.Standards.Connection.Tls.Tls13.Model;
using Arctium.Standards.Connection.Tls.Tls13.Model.Extensions;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;

namespace Arctium.Standards.Connection.Tls.Tls13.Protocol
{
    internal class Tls13ClientProtocol
    {
        public byte[] ApplicationDataBuffer { get; private set; }
        public int ApplicationDataLength { get { return applicationDataLength; } }

        class Context
        {
            public ClientHello ClientHello1;
            public ServerHello HelloRetryRequest;
            public ClientHello ClientHello2;
            public bool CertificateRequest;
        }

        Context context;
        Tls13ClientConfig config;
        ClientProtocolState state;
        Queue<ClientProtocolCommand> commandQueue;
        Crypto crypto;
        byte[] privateKey;
        MessageIO messageIO;
        Validate validate;
        HandshakeContext hscontext;
        ClientProtocolCommand currentCommand;

        byte[] writeApplicationDataBuffer;
        long writeApplicationDataOffset;
        long writeApplicationDataLength;
        int applicationDataLength;

        public Tls13ClientProtocol(Stream networkRawStream, Tls13ClientConfig config)
        {
            this.config = config;
            this.context = new Context();
            this.crypto = new Crypto(Endpoint.Client, null);
            validate = new Validate();
            hscontext = new HandshakeContext();
            messageIO = new MessageIO(networkRawStream, validate, hscontext);
            ApplicationDataBuffer = new byte[Tls13Const.RecordLayer_MaxPlaintextApplicationDataLength];

            commandQueue = new Queue<ClientProtocolCommand>();
        }

        public void Connect()
        {
            commandQueue.Enqueue(ClientProtocolCommand.Start_Connect);

            ProcessCommand();
        }

        private void ProcessCommand(ClientProtocolCommand command)
        {
            commandQueue.Enqueue(command);
            ProcessCommand();
        }

        private void ProcessCommand()
        {
            try
            {
                InnerProcessCommand();
            }
            catch (System.Exception)
            {

                throw;
            }
        }

        private void InnerProcessCommand()
        {
            while (commandQueue.TryDequeue(out currentCommand))
            {
                switch (state)
                {
                    case ClientProtocolState.Start: Start(); break;
                    case ClientProtocolState.Handshake: Handshake(); break;
                    case ClientProtocolState.Connected: Connected(); break;
                    case ClientProtocolState.PostHandshake: PostHandshake(); break;
                    case ClientProtocolState.Closed: throw new Tls13Exception("Cannot process command because connection is closed"); break;
                    case ClientProtocolState.FatalError: throw new Tls13Exception("Cannot process command because encountered fatal error"); break;
                    default: Validation.ThrowInternal("unrecognized protocol state"); break;
                }
            }
        }

        private void Connected()
        {
            switch (currentCommand)
            {
                case ClientProtocolCommand.Connected_ReadApplicationData: Connected_ReadApplicationData(); break;
                case ClientProtocolCommand.Connected_WriteApplicationData: Connected_WriteApplicationData(); break;
                case ClientProtocolCommand.Connected_ReceivedPostHandshakeMessage: Connected_ReceivedPostHandshakeMessage(); break;
                default: throw new Tls13Exception("invalid operation for this state");
            }
        }

        private void Start()
        {
            switch (currentCommand)
            {
                case ClientProtocolCommand.Start_Connect: Start_Connect(); break;
                default: throw new Tls13Exception("command invalid for this state");
            }
        }

        private void PostHandshake()
        {
            switch (currentCommand)
            {
                case ClientProtocolCommand.PostHandshake_ProcessPostHandshakeMessage: PostHandshake_ProcessPostHandshakeMessage(); break;
                case ClientProtocolCommand.PostHandshake_FinishedProcessingPostHandshakeMessages: PostHandshake_FinishedProcessingPostHandshakeMessages(); break;
                default: throw new Tls13Exception("inavlid command for this state");
            }
        }

        private void Handshake()
        {
            switch (currentCommand)
            {
                case ClientProtocolCommand.Handshake_ClientHello: Handshake_ClientHello(); break;
                case ClientProtocolCommand.Handshake_ServerHello: Handshake_ServerHello();  break;
                case ClientProtocolCommand.Handshake_EncryptedExtensions: Handshake_EncryptedExtensions();  break;
                case ClientProtocolCommand.Handshake_CertificateRequest: Handshake_CertificateRequest();  break;
                case ClientProtocolCommand.Handshake_ServerCertificate: Handshake_ServerCertificate(); break;
                case ClientProtocolCommand.Handshake_ServerCertificateVerify: Handshake_ServerCertificateVerify(); break;
                case ClientProtocolCommand.Handshake_ServerFinished: Handshake_ServerFinished();  break;
                case ClientProtocolCommand.Handshake_ClientCertificate: Handshake_ClientCertificate();  break;
                case ClientProtocolCommand.Handshake_ClientCertificateVerify: Handshake_ClientCertificateVerify(); break;
                case ClientProtocolCommand.Handshake_ClientFinished: Handshake_ClientFinished(); break;
                case ClientProtocolCommand.Handshake_HandshakeCompletedSuccessfully: Handshake_HandshakeCompletedSuccessfully(); break;
                default: throw new Tls13Exception("invalid command for this state"); break;
            }
        }

        public void LoadApplicationData() => ProcessCommand(ClientProtocolCommand.Connected_ReadApplicationData);

        public void WriteApplicationData(byte[] buffer, long offset, long length)
        {
            writeApplicationDataBuffer = buffer;
            writeApplicationDataOffset = offset;
            writeApplicationDataLength = length;

            ProcessCommand(ClientProtocolCommand.Connected_WriteApplicationData);
        }

        private void Connected_ReadApplicationData()
        {
            if (!messageIO.TryLoadApplicationData(ApplicationDataBuffer, 0, out applicationDataLength))
            {
                ProcessCommand(ClientProtocolCommand.Connected_ReceivedPostHandshakeMessage);
            }
        }

        private void PostHandshake_FinishedProcessingPostHandshakeMessages()
        {
            state = ClientProtocolState.Connected;
            ProcessCommand(ClientProtocolCommand.Connected_ReadApplicationData);
        }

        private void PostHandshake_ProcessPostHandshakeMessage()
        {
            var messageType = messageIO.LoadHandshakeMessage();

            if (messageType == HandshakeType.NewSessionTicket)
            {
                var ticket = messageIO.ReadHandshakeMessage<NewSessionTicket>();
                ProcessCommand(ClientProtocolCommand.PostHandshake_FinishedProcessingPostHandshakeMessages);
            }
            else throw new NotSupportedException();
        }

        private void Connected_WriteApplicationData()
        {
            messageIO.WriteApplicationData(writeApplicationDataBuffer, writeApplicationDataOffset, writeApplicationDataLength);
        }

        private void Connected_ReceivedPostHandshakeMessage()
        {
            state = ClientProtocolState.PostHandshake;
            ProcessCommand(ClientProtocolCommand.PostHandshake_ProcessPostHandshakeMessage);
        }

        private void Handshake_HandshakeCompletedSuccessfully()
        {
            // todo post handshake actions
            state = ClientProtocolState.Connected;
            crypto.InitMasterSecret(hscontext);
            
            messageIO.ChangeRecordLayerCrypto(crypto, Crypto.RecordLayerKeyType.ApplicationData);
            
            
            messageIO.SetBackwardCompatibilityMode(false, false);
        }

        private void Handshake_ClientFinished()
        {
            var finishedVerData = crypto.ServerFinished(hscontext);
            var finished = new Finished(finishedVerData);

            messageIO.WriteHandshake(finished);

            commandQueue.Enqueue(ClientProtocolCommand.Handshake_HandshakeCompletedSuccessfully);
        }

        private void Handshake_ClientCertificateVerify()
        {
            throw new Exception(); // todo send verify
            commandQueue.Enqueue(ClientProtocolCommand.Handshake_ClientFinished);
        }

        private void Handshake_ClientCertificate()
        {
            throw new Exception(); // todo 
            commandQueue.Enqueue(ClientProtocolCommand.Handshake_ClientCertificateVerify);
        }

        private void Handshake_ServerFinished()
        {
            var finished = messageIO.ReadHandshakeMessage<Finished>();
            //todo verify finished

            if (context.CertificateRequest) commandQueue.Enqueue(ClientProtocolCommand.Handshake_ClientCertificate);
            else commandQueue.Enqueue(ClientProtocolCommand.Handshake_ClientFinished);
        }

        private void Handshake_ServerCertificateVerify()
        {
            var certVerify = messageIO.ReadHandshakeMessage<CertificateVerify>();

            commandQueue.Enqueue(ClientProtocolCommand.Handshake_ServerFinished);
        }

        private void Handshake_ServerCertificate()
        {
            var certificate = messageIO.ReadHandshakeMessage<Certificate>();

            commandQueue.Enqueue(ClientProtocolCommand.Handshake_ServerCertificateVerify);
        }

        private void Handshake_CertificateRequest()
        {
            var certReq = messageIO.ReadHandshakeMessage<CertificateRequest>();

            commandQueue.Enqueue(ClientProtocolCommand.Handshake_ServerCertificate);
        }

        private void Handshake_EncryptedExtensions()
        {
            var encryptedExt = messageIO.ReadHandshakeMessage<EncryptedExtensions>();

            if (messageIO.LoadHandshakeMessage() == HandshakeType.CertificateRequest)
            {
                context.CertificateRequest = true;
                commandQueue.Enqueue(ClientProtocolCommand.Handshake_CertificateRequest);
            }
            else
            {
                context.CertificateRequest = false;
                commandQueue.Enqueue(ClientProtocolCommand.Handshake_ServerCertificate);
            }
        }

        private void Handshake_ServerHello()
        {
            var sh = messageIO.ReadHandshakeMessage<ServerHello>();

            if (MemOps.Memcmp(sh.Random, ServerHello.RandomSpecialConstHelloRetryRequest))
            {
                validate.Handshake.AlertFatal(context.HelloRetryRequest != null, AlertDescription.UnexpectedMessage, "Already received HelloRetryRequest but received it second time, expected ServerHello");
                // validate retry request

                // hello retry request
                throw new Exception();
                commandQueue.Enqueue(ClientProtocolCommand.Handshake_ClientHello);
                return;
            }
            else
            {
                validate.ServerHello.GeneralServerHelloValidate(sh);
            }

            var keyShare = (KeyShareServerHelloExtension)sh.Extensions.Find(e => e.ExtensionType == ExtensionType.KeyShare);

            crypto.SelectCipherSuite(sh.CipherSuite);
            crypto.SelectEcEcdheGroup(keyShare.ServerShare.NamedGroup);
            crypto.ComputeSharedSecret(keyShare.ServerShare.NamedGroup, this.privateKey, keyShare.ServerShare.KeyExchangeRawBytes);
            
            crypto.InitEarlySecret(hscontext, null);
            crypto.InitHandshakeSecret(hscontext);
            messageIO.ChangeRecordLayerCrypto(crypto, Crypto.RecordLayerKeyType.Handshake);

            commandQueue.Enqueue(ClientProtocolCommand.Handshake_EncryptedExtensions);
        }

        private void Handshake_ClientHello()
        {
            if (context.ClientHello1 != null) throw new Exception("todo ch2");
            
            bool isClientHello1 = context.ClientHello1 == null;

            var random = new byte[Tls13Const.HelloRandomFieldLength];
            byte[] sesId = new byte[Tls13Const.ClientHello_LegacySessionIdMaxLen];
            CipherSuite[] suites = new CipherSuite[] { CipherSuite.TLS_AES_128_GCM_SHA256 };
            List<Extension> extensions = new List<Extension>
            {
                new ClientSupportedVersionsExtension(new ushort[] { 0x0304 }),
                new ProtocolNameListExtension(new byte[][] { System.Text.Encoding.ASCII.GetBytes("http/1.1") })
            };

            if (isClientHello1)
            {
                GlobalConfig.RandomGeneratorCryptSecure(random, 0, random.Length);
                GlobalConfig.RandomGeneratorCryptSecure(sesId, 0, sesId.Length);

                byte[] keyShareToSendRawBytes;
                crypto.GeneratePrivateKeyAndKeyShareToSend(SupportedGroupExtension.NamedGroup.X25519, out keyShareToSendRawBytes, out privateKey);

                extensions.Add(new KeyShareClientHelloExtension(new KeyShareEntry[]
                {
                    new KeyShareEntry(SupportedGroupExtension.NamedGroup.X25519, keyShareToSendRawBytes),
                }));

                extensions.Add(new SupportedGroupExtension(new SupportedGroupExtension.NamedGroup[] { SupportedGroupExtension.NamedGroup.X25519 }));
                extensions.Add(new SignatureSchemeListExtension(new SignatureSchemeListExtension.SignatureScheme[]
                {
                    SignatureSchemeListExtension.SignatureScheme.RsaPssRsaeSha256,
                    SignatureSchemeListExtension.SignatureScheme.RsaPssRsaeSha384,
                    SignatureSchemeListExtension.SignatureScheme.RsaPssRsaeSha512,
                    SignatureSchemeListExtension.SignatureScheme.RsaPssPssSha256,
                    SignatureSchemeListExtension.SignatureScheme.RsaPssPssSha384,
                    SignatureSchemeListExtension.SignatureScheme.RsaPssPssSha512
                }));
            }

            var clientHello = new ClientHello(random, sesId, suites, extensions);
            messageIO.WriteHandshake(clientHello);

            commandQueue.Enqueue(ClientProtocolCommand.Handshake_ServerHello);
            messageIO.SetBackwardCompatibilityMode(compatibilityAllowRecordLayerVersionLower0x0303: false, compatibilitySilentlyDropUnencryptedChangeCipherSpec: true);
        }

        private void Start_Connect()
        {
            state = ClientProtocolState.Handshake;
            commandQueue.Enqueue(ClientProtocolCommand.Handshake_ClientHello);

            messageIO.SetBackwardCompatibilityMode(true, true);
        }
    }
}
