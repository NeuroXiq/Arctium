/*
 *  TLS 1.3 Server Implementation
 *  Implemented by NeuroXiq 2022
 */

using Arctium.Standards.Connection.Tls.Tls13.API;
using Arctium.Standards.Connection.Tls.Tls13.Model;
using Arctium.Standards.Connection.Tls.Tls13.Model.Extensions;
using Arctium.Shared;
using Arctium.Shared.Other;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Standards.X509.X509Cert;

namespace Arctium.Standards.Connection.Tls.Tls13.Protocol
{
    class Tls13ServerProtocol
    {
        /// <summary>
        /// Loaded application data requested bt <see cref="LoadApplicationData"/> method
        /// </summary>
        public byte[] ApplicationDataBuffer { get { return applicationDataBuffer; } }
        
        /// <summary>
        /// Application data length in <see cref="ApplicationDataBuffer"/>
        /// </summary>
        public int ApplicationDataLength { get { return applicationDataLength; } }

        class Context
        {
            public ClientHello ClientHello1;
            public ClientHello ClientHello2;
            public ServerHello HelloRetryRequest;
            //public ServerHello ServerHello;
            //public EncryptedExtensions EncryptedExtensions;
            //public Certificate CertificateServer;
            //public CertificateVerify CertificateVerifyServer;
            //public Certificate CertificateClient;
            //public CertificateVerify CertificateVerifyClient;
            //public Finished FinishedServer;
            //public Finished FinishedClient;

            public CipherSuite SelectedCipherSuite;
            public bool IsPskSessionResumption;
            public PreSharedKeyExchangeModeExtension.PskKeyExchangeMode KeyExchangeMode;
            public int CH2Offset;
            public X509CertWithKey SelectedCertificate;
            public SignatureSchemeListExtension.SignatureScheme? SelectedSignatureScheme;


            public PskTicket SelectedPskTicket { get; internal set; }
        }

        private byte[] applicationDataBuffer = new byte[Tls13Const.RecordLayer_MaxPlaintextApplicationDataLength];
        private int applicationDataLength;

        private byte[] writeApplicationDataBuffer;
        private long writeApplicationDataOffset;
        private long writeApplicationDataLength;

        private Queue<ServerProcolCommand> CommandQueue;
        private ServerProcolCommand Command;
        private ServerProtocolState State;
        private MessageIO messageIO;
        private Crypto crypto;
        private Validate validate;
        private ByteBuffer hsctx;
        private Context context;
        private Tls13ServerConfig config { get { return serverContext.Config; } }
        private Tls13ServerContext serverContext;

        public Tls13ServerProtocol(Stream networkStream, Tls13ServerContext serverContext)
        {
            // this.config = config;
            this.serverContext = serverContext;
            validate = new Validate();
            // handshakeContext = new List<KeyValuePair<HandshakeType, byte[]>>();
            // handshakeContext = new HandshakeContext();
            hsctx = new ByteBuffer();

            messageIO = new MessageIO(networkStream, validate);
            messageIO.OnHandshakeReadWrite += MessageIO_OnHandshakeReadWrite;
            crypto = new Crypto(Endpoint.Server, config);
            context = new Context();
            applicationDataLength = 0;
            CommandQueue = new Queue<ServerProcolCommand>();
        }

        private void MessageIO_OnHandshakeReadWrite(byte[] buffer, int offset, int length)
        {
            hsctx.Append(buffer, offset, length);
        }

        public void Listen()
        {
            CommandQueue.Enqueue(ServerProcolCommand.Start);
            State = ServerProtocolState.Listen;

            ProcessCommandLoop();
        }

        public void Close()
        {
        }

        /// <summary>
        /// Removes all data from <see cref="ApplicationDataBuffer"/> and loads next part of application data received.
        /// Result length of data is in <see cref="ApplicationDataLength"/>.
        /// </summary>
        public void LoadNextApplicationData()
        {
            CommandQueue.Enqueue(ServerProcolCommand.Connected_LoadApplicationData);

            ProcessCommandLoop();
        }

        public void WriteApplicationData(byte[] buffer, long offset, long length)
        {
            writeApplicationDataBuffer = buffer;
            writeApplicationDataOffset = offset;
            writeApplicationDataLength = length;

            CommandQueue.Enqueue(ServerProcolCommand.Connected_WriteApplicationData);

            ProcessCommandLoop();
        }

        void ProcessCommandLoop()
        {
            while (CommandQueue.Count > 0)
            {
                Command = CommandQueue.Dequeue();

                switch (State)
                {
                    case ServerProtocolState.Listen: ListenState(); break;
                    case ServerProtocolState.Handshake: HandshakeState();  break;
                    case ServerProtocolState.Connected: ConnectedState();  break;
                    case ServerProtocolState.PostHandshake: PostHandshakeState(); break;
                    default: throw new Tls13Exception("internal: invalid state");
                }
            }
        }

        private void PostHandshakeState()
        {
            switch (Command)
            {
                case ServerProcolCommand.PostHandshake_NewSessionTicket: PostHandshake_NewSessionTicket(); break;
                default: throw new Tls13Exception("command not valid for this state");
            }
        }

        private void ListenState()
        {
            if (Command != ServerProcolCommand.Start) throw new Tls13Exception("Command not valid for this state");

            State = ServerProtocolState.Handshake;
            CommandQueue.Enqueue(ServerProcolCommand.Handshake_FirstClientHello);
        }

        private void ConnectedState()
        {
            switch (Command)
            {
                case ServerProcolCommand.Connected_LoadApplicationData: LoadApplicationData(); break;
                case ServerProcolCommand.LoadApplicationDataNotReceivedApplicationDataContent: LoadApplicationDataNotReceivedApplicationDataContent(); break;
                case ServerProcolCommand.Connected_WriteApplicationData: WriteApplicationData(); break;
                default: throw new NotImplementedException("connected");
            }
        }

        private void HandshakeState()
        {
            switch (Command)
            {
                case ServerProcolCommand.Handshake_FirstClientHello: FirstClientHello(); break;
                case ServerProcolCommand.Handshake_ClientHello1: ClientHello1(); break;
                case ServerProcolCommand.Handshake_SendHelloRetryRequestIfNeeded: Handshake_SendHelloRetryRequestIfNeeded(); break;
                case ServerProcolCommand.Handshake_ServerHelloNotPsk: ServerHelloNotPsk();  break;
                case ServerProcolCommand.Handshake_ServerHelloPsk_Dhe: Handshake_ServerHelloPsk_Dhe(); break;
                case ServerProcolCommand.Handshake_EncryptedExtensions: EncryptedExtensions(); break;
                case ServerProcolCommand.Handshake_ServerCertificate: ServerCertificate();  break;
                case ServerProcolCommand.Handshake_ServerCertificateVerify: ServerCertificateVerify();  break;
                case ServerProcolCommand.Handshake_ServerFinished: ServerFinished(); break;
                case ServerProcolCommand.Handshake_ClientFinished: ClientFinished(); break;
                case ServerProcolCommand.Handshake_HandshakeCompletedSuccessfully: Handshake_HandshakeCompletedSuccessfully(); break;
                case ServerProcolCommand.Handshake_CertificateRequest: Handshake_CertificateRequest(); break;
                case ServerProcolCommand.Handshake_ClientCertificate: Handshake_ClientCertificate(); break;
                case ServerProcolCommand.Handshake_ClientCertificateVerify: Handshake_ClientCertificateVerity(); break;
                default: throw new Tls13Exception("command not valid for this state");
            }
        }

        private void PostHandshake_NewSessionTicket()
        {
            uint lifetime = 3 * 60;
            uint ageAdd = (uint)System.Environment.TickCount;
            byte[] nonce = Guid.NewGuid().ToByteArray();
            byte[] ticket = Guid.NewGuid().ToByteArray();

            NewSessionTicket newSessTicket = new NewSessionTicket(lifetime, ageAdd, nonce, ticket, new Extension[0]);
            
            serverContext.SavePskTicket(crypto.ResumptionMasterSecret,
                newSessTicket.Ticket,
                newSessTicket.TicketNonce,
                newSessTicket.TicketLifetime,
                newSessTicket.TicketAgeAdd,
                crypto.SelectedCipherSuiteHashFunctionId);

            messageIO.WriteHandshake(newSessTicket);

            //Command = ServerProcolCommand.BreakLoopWaitForOtherCommand;
            State = ServerProtocolState.Connected;
        }

        private void Handshake_HandshakeCompletedSuccessfully()
        {
            if (config.UseNewSessionTicketPsk)
            {
                for (int i = 0; i < 1; i++) CommandQueue.Enqueue(ServerProcolCommand.PostHandshake_NewSessionTicket);
                State = ServerProtocolState.PostHandshake;
            }
            else
            {
                //CommandQueue.Enqueue(ServerProcolCommand.BreakLoopWaitForOtherCommand);
                State = ServerProtocolState.Connected;
            }

            messageIO.OnHandshakeReadWrite -= MessageIO_OnHandshakeReadWrite;

            if (context.IsPskSessionResumption)
            {
                var x = 0;
            }

            if (context.HelloRetryRequest != null)
            {
                var t = "";
            }

            if (config.HandshakeRequestCertificateFromClient)
            {
                var x = "";
            }
        }

        private void LoadApplicationDataNotReceivedApplicationDataContent()
        {
            // TODO for example KeyUpdate handshake message
            throw new NotImplementedException();
        }

        private void WriteApplicationData()
        {
            if (applicationDataLength > 0)
            {
                messageIO.WriteApplicationData(writeApplicationDataBuffer, writeApplicationDataOffset, writeApplicationDataLength);
            }
        }

        private void LoadApplicationData()
        {
            if (!messageIO.TryLoadApplicationData(applicationDataBuffer, 0, out applicationDataLength))
            {
                CommandQueue.Enqueue(ServerProcolCommand.LoadApplicationDataNotReceivedApplicationDataContent);
            }
        }

        private void ClientFinished()
        {
            var finished = messageIO.ReadHandshakeMessage<Finished>();

            validate.Finished.FinishedSigValid(crypto.VerifyClientFinished(finished.VerifyData, hsctx));

            // crypto.InitMasterSecret2(handshakeContext);
            messageIO.ChangeRecordLayerCrypto(crypto, Crypto.RecordLayerKeyType.ApplicationData);
            
            messageIO.SetBackwardCompatibilityMode(
                compatibilityAllowRecordLayerVersionLower0x0303: false,
                compatibilitySilentlyDropUnencryptedChangeCipherSpec: false);

            State = ServerProtocolState.Handshake;
            crypto.SetupResumptionMasterSecret(hsctx);

            CommandQueue.Enqueue(ServerProcolCommand.Handshake_HandshakeCompletedSuccessfully);
        }

        private void ServerFinished()
        {
            var finishedVerifyData = crypto.ServerFinished(hsctx);
            var finished = new Finished(finishedVerifyData);

            messageIO.WriteHandshake(finished);
            crypto.SetupMasterSecret(hsctx);
        }

        private void ServerCertificateVerify()
        {
            var signature = crypto.GenerateServerCertificateVerifySignature(hsctx, context.SelectedCertificate, context.SelectedSignatureScheme.Value);

            var certificateVerify = new CertificateVerify(crypto.SelectedSignatureScheme, signature);

            messageIO.WriteHandshake(certificateVerify);
        }

        private void ServerCertificate()
        {
            var certificate = new Certificate(new byte[0], new CertificateEntry[]
            {
                new CertificateEntry(CertificateType.X509, X509Util.X509CertificateToDerEncodedBytes(context.SelectedCertificate.Certificate), new Extension[0])
            });

            messageIO.WriteHandshake(certificate);
        }

        private void Handshake_ClientCertificateVerity()
        {
            var certVer = messageIO.ReadHandshakeMessage<CertificateVerify>();

            // todo implement this
            if (!crypto.VerifyClientCertificate(certVer))
            {
                Validation.ThrowInternal("todo implement (send fatal alert)");
            }
        }

        private void Handshake_ClientCertificate()
        {
            //messageIO.recordLayer.Read();
            var certificate = messageIO.ReadHandshakeMessage<Certificate>();

            if (certificate.CertificateList.Length > 0)
            {
                CommandQueue.Enqueue(ServerProcolCommand.Handshake_ClientCertificateVerify);
            }

            CommandQueue.Enqueue(ServerProcolCommand.Handshake_ClientFinished);
        }

        private void Handshake_CertificateRequest()
        {
            // extension with signature algorithms must be specified 
            var ext = new Extension[]
            {
                new SignatureSchemeListExtension(new SignatureSchemeListExtension.SignatureScheme[]
                {
                    SignatureSchemeListExtension.SignatureScheme.RsaPssRsaeSha256,
                    SignatureSchemeListExtension.SignatureScheme.RsaPkcs1Sha256,
                    SignatureSchemeListExtension.SignatureScheme.RsaPkcs1Sha384,
                    SignatureSchemeListExtension.SignatureScheme.RsaPkcs1Sha512,
                    SignatureSchemeListExtension.SignatureScheme.EcdsaSecp256r1Sha256,
                    SignatureSchemeListExtension.SignatureScheme.EcdsaSecp384r1Sha384,
                    SignatureSchemeListExtension.SignatureScheme.EcdsaSecp521r1Sha512,
                    SignatureSchemeListExtension.SignatureScheme.RsaPssRsaeSha256,
                    SignatureSchemeListExtension.SignatureScheme.RsaPssRsaeSha384,
                    SignatureSchemeListExtension.SignatureScheme.RsaPssRsaeSha512,
                    SignatureSchemeListExtension.SignatureScheme.Ed25519,
                    SignatureSchemeListExtension.SignatureScheme.Ed448,
                    SignatureSchemeListExtension.SignatureScheme.RsaPssPssSha256,
                    SignatureSchemeListExtension.SignatureScheme.RsaPssPssSha384,
                    SignatureSchemeListExtension.SignatureScheme.RsaPssPssSha512,
                    SignatureSchemeListExtension.SignatureScheme.RsaPkcs1Sha1,
                    SignatureSchemeListExtension.SignatureScheme.EcdsaSha1,
                }, ExtensionType.SignatureAlgorithms)
            };

            var certRequest = new CertificateRequest(new byte[0], ext);

            messageIO.WriteHandshake(certRequest);
            //messageIO.recordLayer.Read();
        }

        private void EncryptedExtensions()
        {
            Extension[] extensions = new Extension[]
            {
                new ProtocolNameListExtension(new byte[][] { System.Text.Encoding.ASCII.GetBytes("http/1.1") })
            };

            var encryptedExtensions = new EncryptedExtensions(extensions);

            messageIO.WriteHandshake(encryptedExtensions);
        }

        private void Handshake_ServerHelloPsk_Dhe()
        {
            var clientHello = context.ClientHello2 ?? context.ClientHello1;
            var random = new byte[Tls13Const.HelloRandomFieldLength];
            var legacySessionId = context.ClientHello1.LegacySessionId;
            List<Extension> extensions = new List<Extension>
            {
                ServerSupportedVersionsExtension.ServerHelloTls13,
            };

            PreSharedKeyClientHelloExtension preSharedKeyExtension = clientHello.GetExtension<PreSharedKeyClientHelloExtension>(ExtensionType.PreSharedKey);
            KeyShareEntry clientKeyShare = null;

            GlobalConfig.RandomGeneratorCryptSecure(random, 0, random.Length);

            int selectedClientIdentity;
            var pskTicket = serverContext.GetPskTicket(preSharedKeyExtension, crypto.SelectedCipherSuiteHashFunctionId, out selectedClientIdentity);

            if (selectedClientIdentity == -1)
            {
                // cannot find identity (ticket) for some reason,
                // reason not important (may delete from db, not want to select because of some security restrictions, all tickets expired etc.),
                // go with full crypto (full handshake)
                CommandQueue.Enqueue(ServerProcolCommand.Handshake_ServerHelloNotPsk);
                return;
            }

            context.IsPskSessionResumption = true;

            byte[] psk = crypto.GeneratePsk(pskTicket.ResumptionMasterSecret, pskTicket.TicketNonce);

            crypto.SetupEarlySecret(psk);

            int clientHelloWithBindersOffs = context.ClientHello2 != null ? context.CH2Offset : 0;
            int toBinders = ModelDeserialization.HelperGetOffsetOfPskExtensionInClientHello(hsctx.Buffer, clientHelloWithBindersOffs);

            validate.Handshake.AlertFatal(
                !crypto.IsPskBinderValueValid(hsctx, toBinders, preSharedKeyExtension.Binders[selectedClientIdentity]),
                AlertDescription.DecryptError, "binder value invalid");

            extensions.Add(new PreSharedKeyServerHelloExtension((ushort)selectedClientIdentity));

            clientKeyShare = (context.ClientHello2 ?? context.ClientHello1).GetExtension<KeyShareClientHelloExtension>(ExtensionType.KeyShare)
                        .ClientShares.FirstOrDefault(share => share.NamedGroup == crypto.SelectedNamedGroup);
            // var keyShareToSend = crypto.GenerateSharedSecretAndGetKeyShareToSend(clientKeyShare);

            byte[] keyShareToSendRawBytes, privateKey;
            crypto.GeneratePrivateKeyAndKeyShareToSend(clientKeyShare.NamedGroup, out keyShareToSendRawBytes, out privateKey);
            crypto.ComputeSharedSecret(clientKeyShare.NamedGroup, privateKey, clientKeyShare.KeyExchangeRawBytes);

            extensions.Add(new KeyShareServerHelloExtension(new KeyShareEntry(crypto.SelectedNamedGroup, keyShareToSendRawBytes)));

            var serverHello = new ServerHello(random, legacySessionId, crypto.SelectedCipherSuite, extensions);

            messageIO.WriteHandshake(serverHello);

            crypto.SetupHandshakeSecret(hsctx);
            messageIO.ChangeRecordLayerCrypto(crypto, Crypto.RecordLayerKeyType.Handshake);

            CommandQueue.Enqueue(ServerProcolCommand.Handshake_EncryptedExtensions);
            CommandQueue.Enqueue(ServerProcolCommand.Handshake_ServerFinished);
            CommandQueue.Enqueue(ServerProcolCommand.Handshake_ClientFinished);
        }

        private void ServerHelloNotPsk()
        {
            // full crypto (not PSK), select: ciphersuite, (ec)dhe group, signature algorithm
            SignatureSchemeListExtension clientSupporetdCertSignatures = null;
            var clientSupportedSignatures = context.ClientHello1.GetExtension<SignatureSchemeListExtension>(ExtensionType.SignatureAlgorithms).Schemes;
            context.ClientHello1.TryGetExtension<SignatureSchemeListExtension>(ExtensionType.SignatureAlgorithmsCert, out clientSupporetdCertSignatures);

            bool selectedOk = crypto.SelectSigAlgoAndCert(
                clientSupportedSignatures,
                clientSupporetdCertSignatures?.Schemes,
                config.CertificatesWithKeys,
                ref context.SelectedSignatureScheme,
                ref context.SelectedCertificate);

            validate.Handshake.AlertFatal(!selectedOk, AlertDescription.HandshakeFailure, "configured x509 certificates and signatue schemes does not match mutually with supported with client");

            var clientHello = context.ClientHello2 ?? context.ClientHello1;
            KeyShareEntry keyShareEntry = null;
            ServerHello serverHello;
            var random = new byte[Tls13Const.HelloRandomFieldLength];
            var legacySessId = context.ClientHello1.LegacySessionId;

            List<Extension> extensions = new List<Extension>()
            {
                ServerSupportedVersionsExtension.ServerHelloTls13, //todo uncomment
            };

            keyShareEntry = clientHello.GetExtension<KeyShareClientHelloExtension>(ExtensionType.KeyShare)
                .ClientShares
                .FirstOrDefault(share => share.NamedGroup == crypto.SelectedNamedGroup);

            GlobalConfig.RandomGeneratorCryptSecure(random, 0, random.Length);

            // todo validate if set on ch2

            byte[] keyShareToSendRawBytes, privateKey;
            
            crypto.GeneratePrivateKeyAndKeyShareToSend(keyShareEntry.NamedGroup, out keyShareToSendRawBytes, out privateKey);
            crypto.ComputeSharedSecret(keyShareEntry.NamedGroup, privateKey, keyShareEntry.KeyExchangeRawBytes);

            extensions.Add(new KeyShareServerHelloExtension(new KeyShareEntry(crypto.SelectedNamedGroup, keyShareToSendRawBytes)));

            serverHello = new ServerHello(random,
                legacySessId,
                crypto.SelectedCipherSuite,
                extensions);

            messageIO.WriteHandshake(serverHello);

            crypto.SetupEarlySecret(null);
            crypto.SetupHandshakeSecret(hsctx);

            messageIO.ChangeRecordLayerCrypto(crypto, Crypto.RecordLayerKeyType.Handshake);

            CommandQueue.Enqueue(ServerProcolCommand.Handshake_EncryptedExtensions);

            if (config.HandshakeRequestCertificateFromClient)
            {
                CommandQueue.Enqueue(ServerProcolCommand.Handshake_CertificateRequest);
            }
            
            CommandQueue.Enqueue(ServerProcolCommand.Handshake_ServerCertificate);
            CommandQueue.Enqueue(ServerProcolCommand.Handshake_ServerCertificateVerify);
            CommandQueue.Enqueue(ServerProcolCommand.Handshake_ServerFinished);

            if (config.HandshakeRequestCertificateFromClient)
            {
                CommandQueue.Enqueue(ServerProcolCommand.Handshake_ClientCertificate);
            }
            else
            {
                CommandQueue.Enqueue(ServerProcolCommand.Handshake_ClientFinished);
            }
        }

        private void Handshake_SendHelloRetryRequestIfNeeded()
        {
            var clientShares = context.ClientHello1.GetExtension<KeyShareClientHelloExtension>(ExtensionType.KeyShare).ClientShares;
            var random = new byte[Tls13Const.HelloRandomFieldLength];
            var legacySessionId = context.ClientHello1.LegacySessionId;


            bool retryNeeded = !clientShares.Any(share => share.NamedGroup == crypto.SelectedNamedGroup);
            bool hasPskExtension = context.ClientHello1.TryGetExtension<PreSharedKeyClientHelloExtension>(ExtensionType.PreSharedKey, out _);

            if (retryNeeded)
            {
                random = ServerHello.RandomSpecialConstHelloRetryRequest;
                List<Extension> extensions = new List<Extension>
                {
                    ServerSupportedVersionsExtension.ServerHelloTls13,
                };

                extensions.Add(new KeyShareHelloRetryRequestExtension(crypto.SelectedNamedGroup));
                context.HelloRetryRequest = new ServerHello(random, legacySessionId, crypto.SelectedCipherSuite, extensions);

                crypto.ReplaceClientHello1WithMessageHash(hsctx, hsctx.DataLength);
                messageIO.WriteHandshake(context.HelloRetryRequest);

                context.CH2Offset = hsctx.DataLength;
                context.ClientHello2 = messageIO.ReadHandshakeMessage<ClientHello>();

                var selectedByServer = ((KeyShareHelloRetryRequestExtension)context.HelloRetryRequest.Extensions.First(ext => ext.ExtensionType == ExtensionType.KeyShare)).SelectedGroup;
                var sharedFromClient = context.ClientHello2.GetExtension<KeyShareClientHelloExtension>(ExtensionType.KeyShare).ClientShares;

                validate.Handshake.AlertFatal(sharedFromClient.Count() != 1 || sharedFromClient[0].NamedGroup != selectedByServer,
                    AlertDescription.Illegal_parameter,
                    "Invalid share in ClientHello2 (after HelloRetry). Not single share or other that select on server");

                hasPskExtension = context.ClientHello2.TryGetExtension<PreSharedKeyClientHelloExtension>(ExtensionType.PreSharedKey, out _);
            }

            if (hasPskExtension)
            {
                CommandQueue.Enqueue(ServerProcolCommand.Handshake_ServerHelloPsk_Dhe);
            }
            else
            {
                CommandQueue.Enqueue(ServerProcolCommand.Handshake_ServerHelloNotPsk);
            }
        }

        private void FirstClientHello()
        {
            messageIO.SetBackwardCompatibilityMode(
                compatibilityAllowRecordLayerVersionLower0x0303: true,
                compatibilitySilentlyDropUnencryptedChangeCipherSpec: false);

            CommandQueue.Enqueue(ServerProcolCommand.Handshake_ClientHello1);
        }

        private void ClientHello1()
        {
            ClientHello clientHello = messageIO.ReadHandshakeMessage<ClientHello>();
            validate.ClientHello.GeneralValidateClientHello(clientHello);

            context.ClientHello1 = clientHello;
            PreSharedKeyClientHelloExtension _;

            bool pskKeTicketExists = false, cipherSuiteOk, groupOk;
            bool hasPskExtension = clientHello.TryGetExtension<PreSharedKeyClientHelloExtension>(ExtensionType.PreSharedKey, out _);

            if (hasPskExtension)
            {
                var modes = clientHello.GetExtension<PreSharedKeyExchangeModeExtension>(ExtensionType.PskKeyExchangeModes).KeModes;
                
                if (pskKeTicketExists && modes.Contains(PreSharedKeyExchangeModeExtension.PskKeyExchangeMode.PskKe))
                {
                    CommandQueue.Enqueue(ServerProcolCommand.Handshake_ServerHelloPsk_Ke);
                    return;
                }
            }

            crypto.SelectCipherSuite(clientHello, out cipherSuiteOk);
            crypto.SelectEcEcdheGroup(clientHello, out groupOk);

            validate.Handshake.AlertFatal(!(cipherSuiteOk && groupOk), AlertDescription.HandshakeFailure, "client and server ececdhe or cipher suites does not match mutually");

            CommandQueue.Enqueue(ServerProcolCommand.Handshake_SendHelloRetryRequestIfNeeded);

            messageIO.SetBackwardCompatibilityMode(
                compatibilityAllowRecordLayerVersionLower0x0303: false,
                compatibilitySilentlyDropUnencryptedChangeCipherSpec: true);
        }
    }
}
