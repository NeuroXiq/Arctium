using Arctium.Shared;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Shared.Other;
using Arctium.Standards.Connection.Tls.Tls13.API;
using Arctium.Standards.Connection.Tls.Tls13.Model;
using Arctium.Standards.Connection.Tls.Tls13.Model.Extensions;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;

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

            public PskTicket[] PskTickets;
            public ServerHello ServerHello;

            public int CH1Length = -1;
            public bool IsPskSessionResumption;
        }

        Context context;
        Tls13ClientConfig config { get { return clientContext.Config; } }
        ClientProtocolState state;
        Queue<ClientProtocolCommand> commandQueue;
        Crypto crypto;
        byte[] privateKey;
        MessageIO messageIO;
        Validate validate;
        HandshakeContext hscontext;
        ClientProtocolCommand currentCommand;
        Tls13ClientContext clientContext;
        ByteBuffer hsctx;

        byte[] writeApplicationDataBuffer;
        long writeApplicationDataOffset;
        long writeApplicationDataLength;
        int applicationDataLength;

        public Tls13ClientProtocol(Stream networkRawStream, Tls13ClientContext clientContext)
        {
            this.clientContext = clientContext;
            this.context = new Context();
            this.crypto = new Crypto(Endpoint.Client, null);
            hsctx = new ByteBuffer();
            validate = new Validate();
            hscontext = new HandshakeContext();
            messageIO = new MessageIO(networkRawStream, validate, hscontext);
            ApplicationDataBuffer = new byte[Tls13Const.RecordLayer_MaxPlaintextApplicationDataLength];

            commandQueue = new Queue<ClientProtocolCommand>();
            messageIO.OnHandshakeReadWrite += MessageIO_OnHandshakeReadWrite;
        }

        private void MessageIO_OnHandshakeReadWrite(byte[] buffer, int offset, int length)
        {
            bool ch1 = hsctx.DataLength == 0;

            hsctx.Append(buffer, offset, length);

            if (ch1) context.CH1Length = length;
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
            //try
            {
                InnerProcessCommand();
            }
            //catch (System.Exception)
            {

                //throw;
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
                case ClientProtocolCommand.Handshake_ClientHello1: Handshake_ClientHello1(); break;
                case ClientProtocolCommand.Handshake_ServerHelloOrHelloRetryRequest: Handshake_ServerHelloOrHelloRetryRequest(); break;
                case ClientProtocolCommand.Handshake_ClientHello2: Handshake_ClientHello2(); break;
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
                clientContext.SaveTicket(ticket.Ticket,
                    ticket.TicketNonce,
                    crypto.ResumptionMasterSecret,
                    ticket.TicketLifetime,
                    ticket.TicketAgeAdd,
                    crypto.SelectedCipherSuiteHashFunctionId);

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
            
            // crypto.InitMasterSecret(hscontext);
            
            messageIO.ChangeRecordLayerCrypto(crypto, Crypto.RecordLayerKeyType.ApplicationData);
            
            
            messageIO.SetBackwardCompatibilityMode(false, false);
        }

        private void Handshake_ClientFinished()
        {
            var finishedVerData = crypto.ServerFinished(hsctx);
            var finished = new Finished(finishedVerData);

            crypto.SetupMasterSecret(hsctx);
            messageIO.WriteHandshake(finished);
            crypto.SetupResumptionMasterSecret(hsctx);


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

            if (context.IsPskSessionResumption) commandQueue.Enqueue(ClientProtocolCommand.Handshake_ServerFinished);
            else if (messageIO.LoadHandshakeMessage() == HandshakeType.CertificateRequest)
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
            bool onHelloRetry = context.HelloRetryRequest != null;
            var sh = context.ServerHello;

            validate.ServerHello.GeneralServerHelloValidate(context.ClientHello2, sh);

            var keyShare = (KeyShareServerHelloExtension)sh.Extensions.Find(e => e.ExtensionType == ExtensionType.KeyShare);
            var preSharedKeySh = sh.Extensions.FirstOrDefault(ext => ext.ExtensionType == ExtensionType.PreSharedKey) as PreSharedKeyServerHelloExtension;
            byte[] psk = null;

            if (!onHelloRetry) crypto.SelectCipherSuite(sh.CipherSuite);

            // todo check if server response is correct compared to sended CH (check if this class send keyexchangemode.psk_ke)
            if (keyShare.ServerShare == null) throw new NotSupportedException();
            else
            {
                crypto.SelectEcEcdheGroup(keyShare.ServerShare.NamedGroup);
                crypto.ComputeSharedSecret(keyShare.ServerShare.NamedGroup, this.privateKey, keyShare.ServerShare.KeyExchangeRawBytes);
            }

            if (preSharedKeySh != null)
            {
                validate.ServerHello.AlertFatal(preSharedKeySh.SelectedIdentity >= context.PskTickets.Length, AlertDescription.Illegal_parameter, "server send selected identity out of range");
                var ticket = context.PskTickets[preSharedKeySh.SelectedIdentity];
                psk = crypto.GeneratePsk(ticket.ResumptionMasterSecret, ticket.TicketNonce);
                context.IsPskSessionResumption = true;
            }

            // crypto.InitEarlySecret(hscontext, null);
            // crypto.InitHandshakeSecret(hscontext);

            crypto.SetupEarlySecret(psk);

            crypto.SetupHandshakeSecret(hsctx);

            messageIO.ChangeRecordLayerCrypto(crypto, Crypto.RecordLayerKeyType.Handshake);

            commandQueue.Enqueue(ClientProtocolCommand.Handshake_EncryptedExtensions);
        }

        private void Handshake_ClientHello2()
        {
            // process HelloRetryRequst
            crypto.SelectCipherSuite(context.HelloRetryRequest.CipherSuite);

            // need to replace ClientHello1 (when HelloRetryRequest) with artificial 'Message Hash' message
            // in handshake context bytes (for transcript hash) for future calculations

            crypto.ReplaceClientHello1WithMessageHash(hsctx, context.CH1Length);

            var extensions2 = context.ClientHello1.Extensions.Where(ext => ext.ExtensionType != ExtensionType.KeyShare).ToList();

            var serverKeyShare = (KeyShareHelloRetryRequestExtension)context.HelloRetryRequest.Extensions.First(ext => ext.ExtensionType == ExtensionType.KeyShare);

            byte[] keyShareToSendRawBytes;
            crypto.GeneratePrivateKeyAndKeyShareToSend(serverKeyShare.SelectedGroup, out keyShareToSendRawBytes, out privateKey);

            extensions2.Add(new KeyShareClientHelloExtension(new KeyShareEntry[] { new KeyShareEntry(serverKeyShare.SelectedGroup, keyShareToSendRawBytes) }));

            // todo compute binder values again

            var hello2 = new ClientHello(context.ClientHello1.Random, context.ClientHello1.LegacySessionId, context.ClientHello1.CipherSuites, extensions2);
            messageIO.WriteHandshake(hello2);
            //
            commandQueue.Enqueue(ClientProtocolCommand.Handshake_ServerHelloOrHelloRetryRequest);
        }

        private void Handshake_ServerHelloOrHelloRetryRequest()
        {
            var sh = messageIO.ReadHandshakeMessage<ServerHello>();

            if (MemOps.Memcmp(sh.Random, ServerHello.RandomSpecialConstHelloRetryRequest))
            {
                validate.Handshake.AlertFatal(context.HelloRetryRequest != null, AlertDescription.UnexpectedMessage, "Already received HelloRetryRequest but received it second time, expected ServerHello");
                context.HelloRetryRequest = sh;
                commandQueue.Enqueue(ClientProtocolCommand.Handshake_ClientHello2);
            }
            else
            {
                context.ServerHello = sh;
                commandQueue.Enqueue(ClientProtocolCommand.Handshake_ServerHello);
            }
        }

        private void Handshake_ClientHello1()
        {
            var random = new byte[Tls13Const.HelloRandomFieldLength];
            byte[] sesId = new byte[Tls13Const.ClientHello_LegacySessionIdMaxLen];
            CipherSuite[] suites = new CipherSuite[] { CipherSuite.TLS_AES_128_GCM_SHA256 };
            PreSharedKeyClientHelloExtension preSharedKeyExtension = null;

            List<Extension> extensions = new List<Extension>
            {
                new ClientSupportedVersionsExtension(new ushort[] { 0x0304 }),
                new ProtocolNameListExtension(new byte[][] { System.Text.Encoding.ASCII.GetBytes("http/1.1") }),
                new SignatureSchemeListExtension(new SignatureSchemeListExtension.SignatureScheme[]
                {
                    SignatureSchemeListExtension.SignatureScheme.RsaPssRsaeSha256,
                    SignatureSchemeListExtension.SignatureScheme.RsaPssRsaeSha384,
                    SignatureSchemeListExtension.SignatureScheme.RsaPssRsaeSha512,
                    SignatureSchemeListExtension.SignatureScheme.RsaPssPssSha256,
                    SignatureSchemeListExtension.SignatureScheme.RsaPssPssSha384,
                    SignatureSchemeListExtension.SignatureScheme.RsaPssPssSha512
                }),
                new SupportedGroupExtension(config.SupportedGroups),
                new PreSharedKeyExchangeModeExtension(new PreSharedKeyExchangeModeExtension.PskKeyExchangeMode[] { PreSharedKeyExchangeModeExtension.PskKeyExchangeMode.PskDheKe })
            };

            GlobalConfig.RandomGeneratorCryptSecure(random, 0, random.Length);
            GlobalConfig.RandomGeneratorCryptSecure(sesId, 0, sesId.Length);
            context.PskTickets = clientContext.GetPskTickets();

            byte[] keyShareToSendRawBytes;
            crypto.GeneratePrivateKeyAndKeyShareToSend(config.SupportedGroups[0], out keyShareToSendRawBytes, out privateKey);

            extensions.Add(new KeyShareClientHelloExtension(new KeyShareEntry[]
            {
                    new KeyShareEntry(SupportedGroupExtension.NamedGroup.X25519, keyShareToSendRawBytes),
            }));

            if (context.PskTickets.Length > 0)
            {
                var identities = new List<PreSharedKeyClientHelloExtension.PskIdentity>();
                List<byte[]> binders = new List<byte[]>();

                foreach (var ticket in context.PskTickets)
                {
                    uint obfustatedTicketAge = ticket.TicketLifetime + ticket.TicketAgeAdd;
                    identities.Add(new PreSharedKeyClientHelloExtension.PskIdentity(ticket.Ticket, obfustatedTicketAge));

                    binders.Add(new byte[crypto.GetHashSizeInBytes(ticket.HashFunctionId)]);
                }
                preSharedKeyExtension = new PreSharedKeyClientHelloExtension(identities.ToArray(), binders.ToArray());
                extensions.Add(preSharedKeyExtension);
            }

            var clientHello = new ClientHello(random, sesId, suites, extensions);

            if (context.PskTickets.Length > 0)
            {
                // need to compute binder values, more tricky
                ModelSerialization serialization = new ModelSerialization();
                serialization.ToBytes(clientHello);
                int toBindersLen = ModelDeserialization.HelperGetOffsetOfPskExtensionInClientHello(serialization.SerializedData, 0);

                ByteBuffer hsContextToBinders = new ByteBuffer();
                hsContextToBinders.Append(hsctx.Buffer, 0, hsctx.DataLength);
                hsContextToBinders.Append(serialization.SerializedData, 0, toBindersLen);

                for (int i = 0; i < context.PskTickets.Length; i++)
                {
                    var tic = context.PskTickets[i];
                    var binder = crypto.ComputeBinderValue(hsContextToBinders, tic);

                    preSharedKeyExtension.Binders[i] = binder;
                }

                // hscontext.RemoveLast();
            }

            messageIO.WriteHandshake(clientHello);
            context.ClientHello1 = clientHello;

            // commandQueue.Enqueue(ClientProtocolCommand.Handshake_ServerHello);
            commandQueue.Enqueue(ClientProtocolCommand.Handshake_ServerHelloOrHelloRetryRequest);
            messageIO.SetBackwardCompatibilityMode(compatibilityAllowRecordLayerVersionLower0x0303: false,
                compatibilitySilentlyDropUnencryptedChangeCipherSpec: true);
        }

        private void Start_Connect()
        {
            state = ClientProtocolState.Handshake;
            commandQueue.Enqueue(ClientProtocolCommand.Handshake_ClientHello1);

            messageIO.SetBackwardCompatibilityMode(true, true);
        }
    }
}
