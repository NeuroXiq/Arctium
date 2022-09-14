using Arctium.Connection.Tls.Tls13.API;
using Arctium.Connection.Tls.Tls13.Model;
using Arctium.Connection.Tls.Tls13.Model.Extensions;
using Arctium.Shared;
using Arctium.Shared.Helpers;
using Arctium.Standards;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Arctium.Connection.Tls.Tls13.Protocol
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
            public ClientHello ClientHello;
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
                case ServerProcolCommand.Handshake_ClientHello: ClientHello(); break;
                case ServerProcolCommand.Handshake_ServerHelloNotPsk: ServerHelloNotPsk();  break;
                case ServerProcolCommand.Handshake_ServerHelloPsk: ServerHelloPsk(); break;
                case ServerProcolCommand.Handshake_EncryptedExtensions: EncryptedExtensions(); break;
                case ServerProcolCommand.Handshake_ServerCertificate: ServerCertificate();  break;
                case ServerProcolCommand.Handshake_ServerCertificateVerify: ServerCertificateVerify();  break;
                case ServerProcolCommand.Handshake_ServerFinished: ServerFinished(); break;
                case ServerProcolCommand.Handshake_ClientFinished: ClientFinished(); break;
                case ServerProcolCommand.Handshake_HandshakeCompletedSuccessfully: Handshake_HandshakeCompletedSuccessfully(); break;
                case ServerProcolCommand.Handshake_CertificateRequest:
                case ServerProcolCommand.Handshake_ClientCertificate:
                case ServerProcolCommand.Handshake_ClientCertificateVerify:
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
            serverContext.PskTickets.Add(new Tls13ServerContext.PskTicket(crypto.Ecdhe_or_dhe_SharedSecret, newSessTicket, this.crypto.ResumptionMasterSecret));

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
        }

        private void LoadApplicationDataNotReceivedApplicationDataContent()
        {
            throw new NotImplementedException();
        }

        private void WriteApplicationData()
        {
            if (applicationDataLength > 0)
            {
                messageIO.WriteApplicationData(writeApplicationDataBuffer, writeApplicationDataOffset, writeApplicationDataLength);
            }

           // Command = ServerProcolCommand.BreakLoopWaitForOtherCommand;
        }

        private void LoadApplicationData()
        {
            if (messageIO.TryLoadApplicationData(applicationDataBuffer, 0, out applicationDataLength))
            {
                //Command = ServerProcolCommand.BreakLoopWaitForOtherCommand;
            }
            else
            {
                CommandQueue.Enqueue(ServerProcolCommand.LoadApplicationDataNotReceivedApplicationDataContent);
            }
        }

        private void ClientFinished()
        {
            var finished = messageIO.LoadHandshakeMessage<Finished>();

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

            // todo: or get certificate from client if needed

            //CommandQueue.Enqueue(ServerProcolCommand.Handshake_ClientFinished);
        }

        private void ServerCertificateVerify()
        {
            var signature = crypto.GenerateServerCertificateVerifySignature(handshakeContext);

            var certificateVerify = new CertificateVerify(crypto.SelectedSignatureScheme, signature);

            messageIO.WriteHandshake(certificateVerify);

            //CommandQueue.Enqueue(ServerProcolCommand.Handshake_ServerFinished);
        }

        private void ServerCertificate()
        {
            var certificate = new Certificate(new byte[0], new CertificateEntry[]
            {
                new CertificateEntry(CertificateType.X509, config.DerEncodedCertificateBytes, new Extension[0])
            });

            messageIO.WriteHandshake(certificate);

            //CommandQueue.Enqueue(ServerProcolCommand.Handshake_ServerCertificateVerify);
        }

        private void EncryptedExtensions()
        {
            Extension[] extensions = new Extension[]
            {
                new ProtocolNameListExtension(new byte[][] { System.Text.Encoding.ASCII.GetBytes("http/1.1") })
            };

            var encryptedExtensions = new EncryptedExtensions(extensions);

            messageIO.WriteHandshake(encryptedExtensions);

            //CommandQueue.Enqueue(ServerProcolCommand.Handshake_ServerCertificate);
        }

        private void ServerHelloPsk()
        {
            context.IsPskSessionResumption = true;
            var x = context.ClientHello.GetExtension<PreSharedKeyClientHelloExtension>(ExtensionType.PreSharedKey); //.Extensions.Select(r => r.ExtensionType == ).First();


            PreSharedKeyExchangeModeExtension extMode;
            context.ClientHello.TryGetExtension<PreSharedKeyExchangeModeExtension>(ExtensionType.PskKeyExchangeModes, out extMode);



            //var ticketIssued = this.serverContext.PskTickets.Single(t => MemOps.Memcmp(t.Ticket.Ticket, x.Identities[0].Identity));

            short clientSelected = -1;
            Tls13ServerContext.PskTicket serverSelected = default(Tls13ServerContext.PskTicket);


            // todo must validate binder values
            for (int i = 0; i < x.Identities.Length; i++)
            {
                for (int j = 0; j < this.serverContext.PskTickets.Count; j++)
                {
                    if (MemOps.Memcmp(this.serverContext.PskTickets[j].Ticket.Ticket, x.Identities[i].Identity))
                    {
                        clientSelected = (short)i;
                        serverSelected = this.serverContext.PskTickets[j];
                    }
                }
            }

            if (clientSelected == -1) throw new Exception();

            var random = new byte[Tls13Const.HelloRandomFieldLength];

            var keyShare = context.ClientHello.GetExtension<KeyShareClientHelloExtension>(ExtensionType.KeyShare)
                .ClientShares
                .Single(share => share.NamedGroup == SupportedGroupExtension.NamedGroup.X25519);

            bool groupOk, cipherOk, signOk;

            crypto.SelectSuiteAndEcEcdheGroupAndSigAlgo(context.ClientHello, out groupOk, out cipherOk, out signOk);
            var keyShareToSend = crypto.GenerateSharedSecretAndGetKeyShareToSend(keyShare);
            crypto.SetupPsk(serverSelected.ResumptionMasterSecret, serverSelected.Ticket.TicketNonce);

            var extensions = new Extension[]
            {
                ServerSupportedVersionsExtension.ServerHelloTls13,
                new PreSharedKeyServerHelloExtension((ushort)clientSelected),
                new KeyShareServerHelloExtension(new KeyShareEntry(crypto.SelectedNamedGroup, keyShareToSend)),
                // not send keyshare?
            };

            // crypto.SetupCryptoAlgorithms(CipherSuite.TLS_AES_128_GCM_SHA256, null, serverSelected.Ec_or_Ecdhe);
            

            ServerHello serverHello = new ServerHello(random, context.ClientHello.LegacySessionId, crypto.SelectedCipherSuite, extensions);
            messageIO.WriteHandshake(serverHello);

            crypto.InitEarlySecret(handshakeContext);
            crypto.InitHandshakeSecret(handshakeContext);
            messageIO.ChangeRecordLayerCrypto(crypto, Crypto.RecordLayerKeyType.Handshake);

            messageIO.SetBackwardCompatibilityMode(true, true);


            // messageIO.TryLoadApplicationData(applicationDataBuffer, 0, out applicationDataLength);

            // CommandQueue.Enqueue(ServerProcolCommand.Handshake_EncryptedExtensions);
        }

        private void ServerHelloNotPsk()
        {
            // full crypto (not PSK), select: ciphersuite, (ec)dhe group, signature algorithm

            bool groupOk, cipherSuiteOk, signAlgoOk;
            crypto.SelectSuiteAndEcEcdheGroupAndSigAlgo(context.ClientHello, out groupOk, out cipherSuiteOk, out signAlgoOk);
            validate.Handshake.SelectedSuiteAndEcEcdheGroupAndSignAlgo(groupOk, cipherSuiteOk, signAlgoOk);

            var keyShare = context.ClientHello.GetExtension<KeyShareClientHelloExtension>(ExtensionType.KeyShare)
                .ClientShares
                .Single(share => share.NamedGroup == crypto.SelectedNamedGroup);

            var random = new byte[Tls13Const.HelloRandomFieldLength];
            var keyShareToSend = crypto.GenerateSharedSecretAndGetKeyShareToSend(keyShare);

            var extensions = new Extension[]
            {
                ServerSupportedVersionsExtension.ServerHelloTls13,
                new KeyShareServerHelloExtension(new KeyShareEntry(crypto.SelectedNamedGroup, keyShareToSend))
            };

            ServerHello serverHello = new ServerHello(random, context.ClientHello.LegacySessionId, crypto.SelectedCipherSuite, extensions);

            messageIO.WriteHandshake(serverHello);

            crypto.InitEarlySecret(handshakeContext);
            crypto.InitHandshakeSecret(handshakeContext);

            messageIO.ChangeRecordLayerCrypto(crypto, Crypto.RecordLayerKeyType.Handshake);

            //CommandQueue.Enqueue(ServerProcolCommand.Handshake_EncryptedExtensions);
        }

        private void FirstClientHello()
        {
            // messageIO.SetState(MessageIOState.FirstClientHello);
            messageIO.SetBackwardCompatibilityMode(
                compatibilityAllowRecordLayerVersionLower0x0303: true,
                compatibilitySilentlyDropUnencryptedChangeCipherSpec: false);

            CommandQueue.Enqueue(ServerProcolCommand.Handshake_ClientHello);
        }

        private void ClientHello()
        {
            ClientHello clientHello = messageIO.LoadHandshakeMessage<ClientHello>();

            // select cipher suite
            //int i = 0;
            //for (; i < crypto.SupportedCipherSuites.Count; i++)
            //    for (int j = 0; j < clientHello.CipherSuites.Length; j++)
            //        if (clientHello.CipherSuites[j] == crypto.SupportedCipherSuites[i]) break;

            //validate.ClientHello.GeneralValidateClientHello(clientHello);
            //validate.Handshake.CipherSuitesNotOverlapWithSupported(i == crypto.SupportedCipherSuites.Count);

            //// select supported groups
            //var clientKeyShare = clientHello.GetExtension<KeyShareClientHelloExtension>(ExtensionType.KeyShare);

            //var x255group = clientHello.GetExtension<SupportedGroupExtension>(ExtensionType.SupportedGroups)
            //    .NamedGroupList
            //    .Any(g => g == SupportedGroupExtension.NamedGroup.X25519);

            //var x255 = clientKeyShare.ClientShares.FirstOrDefault(share => share.NamedGroup == SupportedGroupExtension.NamedGroup.X25519);

            //validate.Handshake.ClientSupportedGroupsNotOverlapWithImplemented(!x255group);
            //validate.Handshake.ThrowGeneral(x255 != null, "internal not impl. helloretryrequest to implement");

            //// select signature algorithm
            //bool serverAuthenticatesWithCert = true;
            //SignatureSchemeListExtension signaturesExtension = null;

            //validate.ClientHello.MissingSignatureAlgorithmsExtension(serverAuthenticatesWithCert && !clientHello.TryGetExtension(ExtensionType.SignatureAlgorithms, out signaturesExtension));

            //bool containsAnySupportedSignature = signaturesExtension.Schemes.Any(scheme => scheme == SignatureSchemeListExtension.SignatureScheme.RsaPssRsaeSha256);
            //SignatureSchemeListExtension.SignatureScheme selectedScheme = SignatureSchemeListExtension.SignatureScheme.RsaPssRsaeSha256;

            //validate.ClientHello.SignatureSchemesNotSupported(!containsAnySupportedSignature);

            // todo: if clientkeyshare didn't send crypto arguments need to helloretryrequest

            context.ClientHello = clientHello;

            foreach (var e in clientHello.Extensions) Console.WriteLine(e.ExtensionType.ToString());

            var x = clientHello.Extensions.FirstOrDefault(a => a.ExtensionType == ExtensionType.PreSharedKey);

            if (x != null)
            {
                var y = (PreSharedKeyClientHelloExtension)x;
                CommandQueue.Enqueue(ServerProcolCommand.Handshake_ServerHelloPsk);
                CommandQueue.Enqueue(ServerProcolCommand.Handshake_EncryptedExtensions);
                CommandQueue.Enqueue(ServerProcolCommand.Handshake_ServerFinished);
                CommandQueue.Enqueue(ServerProcolCommand.Handshake_ClientFinished);
            }
            else
            {
                CommandQueue.Enqueue(ServerProcolCommand.Handshake_ServerHelloNotPsk);
                CommandQueue.Enqueue(ServerProcolCommand.Handshake_EncryptedExtensions);
                CommandQueue.Enqueue(ServerProcolCommand.Handshake_ServerCertificate);
                CommandQueue.Enqueue(ServerProcolCommand.Handshake_ServerCertificateVerify);
                CommandQueue.Enqueue(ServerProcolCommand.Handshake_ServerFinished);
                CommandQueue.Enqueue(ServerProcolCommand.Handshake_ClientFinished);
            }

            messageIO.SetBackwardCompatibilityMode(
                compatibilityAllowRecordLayerVersionLower0x0303: false,
                compatibilitySilentlyDropUnencryptedChangeCipherSpec: true);

            
        }
    }
}
