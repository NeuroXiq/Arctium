using Arctium.Standards.Connection.Tls.Tls13.API;
using Arctium.Standards.Connection.Tls.Tls13.Model;
using Arctium.Standards.Connection.Tls.Tls13.Model.Extensions;
using Arctium.Shared;
using Arctium.Shared.Other;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

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
            public byte[] EcdhOrDheSharedSecret;
            public bool IsPskSessionResumption;
            public PreSharedKeyExchangeModeExtension.PskKeyExchangeMode KeyExchangeMode;

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
        // private List<KeyValuePair<HandshakeType, byte[]>> handshakeContext;
        private HandshakeContext handshakeContext;
        private Context context;
        private Tls13ServerConfig config { get { return serverContext.Config; } }
        private Tls13ServerContext serverContext;

        public Tls13ServerProtocol(Stream networkStream, Tls13ServerContext serverContext)
        {
            // this.config = config;
            this.serverContext = serverContext;
            validate = new Validate();
            // handshakeContext = new List<KeyValuePair<HandshakeType, byte[]>>();
            handshakeContext = new HandshakeContext();

            messageIO = new MessageIO(networkStream, validate, handshakeContext);
            crypto = new Crypto(Endpoint.Server, config);
            context = new Context();
            applicationDataLength = 0;
            CommandQueue = new Queue<ServerProcolCommand>();
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
                case ServerProcolCommand.Handshake_ServerHelloNotPsk: ServerHelloNotPsk();  break;
                case ServerProcolCommand.Handshake_ServerHelloPsk: ServerHelloPsk(); break;
                case ServerProcolCommand.Handshake_EncryptedExtensions: EncryptedExtensions(); break;
                case ServerProcolCommand.Handshake_ServerCertificate: ServerCertificate();  break;
                case ServerProcolCommand.Handshake_ServerCertificateVerify: ServerCertificateVerify();  break;
                case ServerProcolCommand.Handshake_ServerFinished: ServerFinished(); break;
                case ServerProcolCommand.Handshake_ClientFinished: ClientFinished(); break;
                case ServerProcolCommand.Handshake_HandshakeCompletedSuccessfully: Handshake_HandshakeCompletedSuccessfully(); break;
                case ServerProcolCommand.Handshake_HelloRetryRequest: Handshake_HelloRetryRequest(); break;
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
            ticket[0] = ((byte)serverContext.PskTickets.Count); ticket[1] = (byte)(serverContext.PskTickets.Count >> 8);

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
                for (int i = 0; i < 20; i++) PostHandshake_NewSessionTicket();
                CommandQueue.Enqueue(ServerProcolCommand.PostHandshake_NewSessionTicket);
                State = ServerProtocolState.PostHandshake;
            }
            else
            {
                //CommandQueue.Enqueue(ServerProcolCommand.BreakLoopWaitForOtherCommand);
                State = ServerProtocolState.Connected;
            }

            if (context.IsPskSessionResumption)
            {
                var x = 0;
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

            validate.Finished.FinishedSigValid(crypto.VerifyClientFinished(finished.VerifyData, handshakeContext));

            crypto.InitMasterSecret2(handshakeContext);
            messageIO.ChangeRecordLayerCrypto(crypto, Crypto.RecordLayerKeyType.ApplicationData);
            
            messageIO.SetBackwardCompatibilityMode(
                compatibilityAllowRecordLayerVersionLower0x0303: false,
                compatibilitySilentlyDropUnencryptedChangeCipherSpec: false);

            State = ServerProtocolState.Handshake;

            CommandQueue.Enqueue(ServerProcolCommand.Handshake_HandshakeCompletedSuccessfully);
        }

        private void ServerFinished()
        {
            var finishedVerifyData = crypto.ServerFinished(handshakeContext);
            var finished = new Finished(finishedVerifyData);

            messageIO.WriteHandshake(finished);
        }

        private void ServerCertificateVerify()
        {
            var signature = crypto.GenerateServerCertificateVerifySignature(handshakeContext);

            var certificateVerify = new CertificateVerify(crypto.SelectedSignatureScheme, signature);

            messageIO.WriteHandshake(certificateVerify);
        }

        private void ServerCertificate()
        {
            var certificate = new Certificate(new byte[0], new CertificateEntry[]
            {
                new CertificateEntry(CertificateType.X509, config.DerEncodedCertificateBytes, new Extension[0])
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
                })
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

        private void Handshake_HelloRetryRequest()
        {
            messageIO.WriteHandshake(context.HelloRetryRequest);

            context.ClientHello2 = messageIO.ReadHandshakeMessage<ClientHello>();

            var selectedByServer = ((KeyShareHelloRetryRequestExtension)context.HelloRetryRequest.Extensions.First(ext => ext.ExtensionType == ExtensionType.KeyShare)).SelectedGroup;
            var sharedFromClient = context.ClientHello2.GetExtension<KeyShareClientHelloExtension>(ExtensionType.KeyShare).ClientShares;

            validate.Handshake.AlertFatal(sharedFromClient.Count() != 1 || sharedFromClient[0].NamedGroup != selectedByServer,
                AlertDescription.Illegal_parameter,
                "Invalid share in ClientHello2 (after HelloRetry). Not single share or other that select on server");
        }

        private void ServerHelloPsk()
        {
            bool isClientHello1 = context.ClientHello2 == null;
            var random = new byte[Tls13Const.HelloRandomFieldLength];
            var legacySessionId = context.ClientHello1.LegacySessionId;
            List<Extension> extensions = new List<Extension>
            {
                ServerSupportedVersionsExtension.ServerHelloTls13,
            };

            PreSharedKeyClientHelloExtension preSharedKeyExtension;
            KeyShareEntry clientKeyShare = null;

            context.IsPskSessionResumption = true;

            if (isClientHello1)
            {
                ClientHello clientHello = context.ClientHello1;
                bool groupOk = false, cipherOk = false, helloRetryNeeded = false;
                var keyExchangeModes = clientHello.GetExtension<PreSharedKeyExchangeModeExtension>(ExtensionType.PskKeyExchangeModes).KeModes;

                if (keyExchangeModes.Contains(PreSharedKeyExchangeModeExtension.PskKeyExchangeMode.PskDheKe))
                {
                    crypto.SelectCipherSuite(clientHello, out cipherOk);
                    crypto.SelectEcEcdheGroup(clientHello, out groupOk);

                    clientKeyShare = clientHello.GetExtension<KeyShareClientHelloExtension>(ExtensionType.KeyShare)
                        .ClientShares.FirstOrDefault(share => share.NamedGroup == crypto.SelectedNamedGroup);

                    helloRetryNeeded = clientKeyShare == null;
                    context.KeyExchangeMode = PreSharedKeyExchangeModeExtension.PskKeyExchangeMode.PskDheKe;
                }
                else if (keyExchangeModes.Contains(PreSharedKeyExchangeModeExtension.PskKeyExchangeMode.PskKe))
                {
                    crypto.SelectCipherSuite(clientHello, out cipherOk);
                    groupOk = true;
                    context.KeyExchangeMode = PreSharedKeyExchangeModeExtension.PskKeyExchangeMode.PskKe;
                }
                else validate.Handshake.AlertFatal(true, AlertDescription.Illegal_parameter, "keyExchangeModes not supported or illegal param");

                validate.Handshake.AlertFatal(!(cipherOk && groupOk), AlertDescription.HandshakeFailure, "client and server ececdhe or cipher suites does not match mutually");

                if (helloRetryNeeded)
                {
                    random = ServerHello.RandomSpecialConstHelloRetryRequest;
                    extensions.Add(new KeyShareHelloRetryRequestExtension(crypto.SelectedNamedGroup));
                    context.HelloRetryRequest = new ServerHello(random, legacySessionId, crypto.SelectedCipherSuite, extensions);

                    // hello retry needed, send helloretry and go back again to this method
                    CommandQueue.Enqueue(ServerProcolCommand.Handshake_HelloRetryRequest);
                    CommandQueue.Enqueue(ServerProcolCommand.Handshake_ServerHelloPsk);
                    return;
                }

                GlobalConfig.RandomGeneratorCryptSecure(random, 0, random.Length);
                preSharedKeyExtension = context.ClientHello1.GetExtension<PreSharedKeyClientHelloExtension>(ExtensionType.PreSharedKey);
            }
            else
            {
                GlobalConfig.RandomGeneratorCryptSecure(random, 0, random.Length);
                preSharedKeyExtension = context.ClientHello2.GetExtension<PreSharedKeyClientHelloExtension>(ExtensionType.PreSharedKey);
                clientKeyShare = context.ClientHello2.GetExtension<KeyShareClientHelloExtension>(ExtensionType.KeyShare)
                    .ClientShares.FirstOrDefault(share => share.NamedGroup == crypto.SelectedNamedGroup);

                if (clientKeyShare == null) Validation.ThrowInternal("must never happer because is clienthello2");
            }

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

            byte[] psk = crypto.GeneratePsk(pskTicket.ResumptionMasterSecret, pskTicket.TicketNonce);
            crypto.InitEarlySecret(handshakeContext, psk);

            validate.Handshake.AlertFatal(
                !crypto.IsPskBinderValueValid(handshakeContext, pskTicket, preSharedKeyExtension.Binders[selectedClientIdentity]),
                AlertDescription.DecryptError, "binder value invalid");

            extensions.Add(new PreSharedKeyServerHelloExtension((ushort)selectedClientIdentity));

            if (context.KeyExchangeMode == PreSharedKeyExchangeModeExtension.PskKeyExchangeMode.PskDheKe)
            {
                clientKeyShare = (context.ClientHello2 ?? context.ClientHello1).GetExtension<KeyShareClientHelloExtension>(ExtensionType.KeyShare)
                        .ClientShares.FirstOrDefault(share => share.NamedGroup == crypto.SelectedNamedGroup);
                // var keyShareToSend = crypto.GenerateSharedSecretAndGetKeyShareToSend(clientKeyShare);

                byte[] keyShareToSendRawBytes, privateKey;
                crypto.GeneratePrivateKeyAndKeyShareToSend(clientKeyShare.NamedGroup, out keyShareToSendRawBytes, out privateKey);
                crypto.ComputeSharedSecret(clientKeyShare.NamedGroup, privateKey, clientKeyShare.KeyExchangeRawBytes);

                extensions.Add(new KeyShareServerHelloExtension(new KeyShareEntry(crypto.SelectedNamedGroup, keyShareToSendRawBytes)));
            }
            else throw new NotSupportedException();

            var serverHello = new ServerHello(random, legacySessionId, crypto.SelectedCipherSuite, extensions);

            messageIO.WriteHandshake(serverHello);

            crypto.InitHandshakeSecret(handshakeContext);
            messageIO.ChangeRecordLayerCrypto(crypto, Crypto.RecordLayerKeyType.Handshake);

            CommandQueue.Enqueue(ServerProcolCommand.Handshake_EncryptedExtensions);
            CommandQueue.Enqueue(ServerProcolCommand.Handshake_ServerFinished);
            CommandQueue.Enqueue(ServerProcolCommand.Handshake_ClientFinished);
        }

        private void ServerHelloNotPsk()
        {
            // full crypto (not PSK), select: ciphersuite, (ec)dhe group, signature algorithm

            bool isClientHello1 = context.ClientHello2 == null;
            KeyShareEntry keyShareEntry = null;
            ServerHello serverHello;
            var random = new byte[Tls13Const.HelloRandomFieldLength];
            var legacySessId = context.ClientHello1.LegacySessionId;

            List<Extension> extensions = new List<Extension>()
            {
                ServerSupportedVersionsExtension.ServerHelloTls13, //todo uncomment
            };


            if (isClientHello1)
            {
                ClientHello clientHello = context.ClientHello1;
                bool groupOk, cipherSuiteOk, signAlgoOk;
                crypto.SelectSuiteAndEcEcdheGroupAndSigAlgo(context.ClientHello1, out groupOk, out cipherSuiteOk, out signAlgoOk);
                validate.Handshake.SelectedSuiteAndEcEcdheGroupAndSignAlgo(groupOk, cipherSuiteOk, signAlgoOk);

                keyShareEntry = clientHello.GetExtension<KeyShareClientHelloExtension>(ExtensionType.KeyShare)
                    .ClientShares
                    .FirstOrDefault(share => share.NamedGroup == crypto.SelectedNamedGroup);

                serverHello = new ServerHello(random,
                        legacySessId,
                        crypto.SelectedCipherSuite,
                        extensions);

                if (keyShareEntry == null)
                {
                    
                    // hello retry
                    serverHello.Random = ServerHello.RandomSpecialConstHelloRetryRequest;
                    serverHello.Extensions.Add(new KeyShareHelloRetryRequestExtension(crypto.SelectedNamedGroup));
                    //serverHello.Extensions.Add(new CookieExtension(new byte[48]));
                    context.HelloRetryRequest = serverHello;

                    CommandQueue.Enqueue(ServerProcolCommand.Handshake_HelloRetryRequest);
                    CommandQueue.Enqueue(ServerProcolCommand.Handshake_ServerHelloNotPsk);
                    return;
                }
            }
            else
            {
                GlobalConfig.RandomGeneratorCryptSecure(random, 0, random.Length);

                keyShareEntry = context.ClientHello2.GetExtension<KeyShareClientHelloExtension>(ExtensionType.KeyShare)
                    .ClientShares
                    .FirstOrDefault(share => share.NamedGroup == crypto.SelectedNamedGroup);

                if (keyShareEntry == null) Validation.ThrowInternal("impossible must be set after helloretry");

                serverHello = new ServerHello(random, legacySessId, crypto.SelectedCipherSuite, extensions);
            }

            // todo validate if set on ch2

            byte[] keyShareToSendRawBytes, privateKey;
            
            crypto.GeneratePrivateKeyAndKeyShareToSend(keyShareEntry.NamedGroup, out keyShareToSendRawBytes, out privateKey);
            crypto.ComputeSharedSecret(keyShareEntry.NamedGroup, privateKey, keyShareEntry.KeyExchangeRawBytes);

            extensions.Add(new KeyShareServerHelloExtension(new KeyShareEntry(crypto.SelectedNamedGroup, keyShareToSendRawBytes)));
            
            messageIO.WriteHandshake(serverHello);

            crypto.InitEarlySecret(handshakeContext, null);
            crypto.InitHandshakeSecret(handshakeContext);

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

            if (clientHello.TryGetExtension<PreSharedKeyClientHelloExtension>(ExtensionType.PreSharedKey, out _))
            {
                CommandQueue.Enqueue(ServerProcolCommand.Handshake_ServerHelloPsk);
            }
            else
            {
                CommandQueue.Enqueue(ServerProcolCommand.Handshake_ServerHelloNotPsk);
            }

            messageIO.SetBackwardCompatibilityMode(
                compatibilityAllowRecordLayerVersionLower0x0303: false,
                compatibilitySilentlyDropUnencryptedChangeCipherSpec: true);
        }
    }
}
