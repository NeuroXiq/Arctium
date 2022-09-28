using Arctium.Connection.Tls.Tls13.API;
using Arctium.Connection.Tls.Tls13.Model;
using Arctium.Connection.Tls.Tls13.Model.Extensions;
using Arctium.Shared;
using Arctium.Shared.Exceptions;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Binary;
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

            public Tls13ServerContext.PskTicket SelectedPskTicket { get; internal set; }
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
            
            serverContext.SavePskTicket(crypto.Ecdhe_or_dhe_SharedSecret,
                crypto.ResumptionMasterSecret,
                newSessTicket.Ticket,
                newSessTicket.TicketNonce,
                crypto.SelectedCipherSuiteHashFunctionName);

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
            // TODO for example KeyUpdate handshake message
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
            if (!messageIO.TryLoadApplicationData(applicationDataBuffer, 0, out applicationDataLength))
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
            // messageIO.recordLayer.Read();
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

        private void Handshake_HelloRetryRequest()
        {
            messageIO.WriteHandshake(context.HelloRetryRequest);
            context.ClientHello2 = messageIO.LoadHandshakeMessage<ClientHello>();
        }

        private void ServerHelloPsk()
        {
            ClientHello clientHello = context.ClientHello1;
            bool isClientHello1 = context.ClientHello2 == null;
            bool helloRetryNeeded = false;

            context.IsPskSessionResumption = true;

            var preSharedKeyExtension = context.ClientHello1.GetExtension<PreSharedKeyClientHelloExtension>(ExtensionType.PreSharedKey); //.Extensions.Select(r => r.ExtensionType == ).First();
            KeyShareEntry clientKeyShare = null;


            //PreSharedKeyExchangeModeExtension extMode;
            //context.ClientHello1.TryGetExtension<PreSharedKeyExchangeModeExtension>(ExtensionType.PskKeyExchangeModes, out extMode);
            //var ticketIssued = this.serverContext.PskTickets.Single(t => MemOps.Memcmp(t.Ticket.Ticket, x.Identities[0].Identity));


            // todo must validate binder values
            if (isClientHello1)
            {
                bool groupOk = false, cipherOk = false;
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
            }

            var random = new byte[Tls13Const.HelloRandomFieldLength];
            var legacySessionId = context.ClientHello1.LegacySessionId;
            var extensions = new List<Extension>
            {
                ServerSupportedVersionsExtension.ServerHelloTls13,
            };

            if (context.HelloRetryRequest != null)
            {
                random = context.HelloRetryRequest.Random;
            }
            else
            {
                GlobalConfig.RandomGeneratorCryptSecure(random, 0, random.Length);
            }


            if (helloRetryNeeded)
            {
                random = ServerHello.RandomSpecialConstHelloRetryRequest;
                extensions.Add(new KeyShareHelloRetryRequestExtension(crypto.SelectedNamedGroup));
                context.HelloRetryRequest = new ServerHello(random, legacySessionId, crypto.SelectedCipherSuite, extensions);

                // send retry and go back to this method again
                // helloretry = new serverhello(...)
                // messageio.write(helloretry);
                CommandQueue.Enqueue(ServerProcolCommand.Handshake_HelloRetryRequest);
                CommandQueue.Enqueue(ServerProcolCommand.Handshake_ServerHelloPsk);
                return;
            }

            int selectedClientIdentity;
            var pskTicket = serverContext.GetPskTicket(preSharedKeyExtension, crypto.SelectedCipherSuiteHashFunctionName, out selectedClientIdentity);

            if (selectedClientIdentity == -1)
            {
                // cannot find identity (ticket) for some reason,
                // reason not important (may delete from db, not want to select because of some security restrictions, all tickets expired etc.),
                // go with full crypto (full handshake)
                CommandQueue.Enqueue(ServerProcolCommand.Handshake_ServerHelloNotPsk);
                return;
            }

            crypto.SetupPsk(pskTicket.ResumptionMasterSecret, pskTicket.TicketNonce);
            crypto.InitEarlySecret(handshakeContext);

            validate.Handshake.AlertFatal(
                !crypto.IsPskBinderValueValid(handshakeContext, pskTicket, preSharedKeyExtension.Binders[selectedClientIdentity]),
                AlertDescription.DecryptError, "binder value invalid");

            extensions.Add(new PreSharedKeyServerHelloExtension((ushort)selectedClientIdentity));

            if (context.KeyExchangeMode == PreSharedKeyExchangeModeExtension.PskKeyExchangeMode.PskDheKe)
            {
                clientKeyShare = (context.ClientHello2 ?? context.ClientHello1).GetExtension<KeyShareClientHelloExtension>(ExtensionType.KeyShare)
                        .ClientShares.FirstOrDefault(share => share.NamedGroup == crypto.SelectedNamedGroup);
                var keyShareToSend = crypto.GenerateSharedSecretAndGetKeyShareToSend(clientKeyShare);
                extensions.Add(new KeyShareServerHelloExtension(new KeyShareEntry(crypto.SelectedNamedGroup, keyShareToSend)));
            }
            else throw new NotSupportedException();

            var serverHello = new ServerHello(random, legacySessionId, crypto.SelectedCipherSuite, extensions);

            messageIO.WriteHandshake(serverHello);

            crypto.InitHandshakeSecret(handshakeContext);
            messageIO.ChangeRecordLayerCrypto(crypto, Crypto.RecordLayerKeyType.Handshake);
            //decrypt_error

            CommandQueue.Enqueue(ServerProcolCommand.Handshake_EncryptedExtensions);
            CommandQueue.Enqueue(ServerProcolCommand.Handshake_ServerFinished);
            CommandQueue.Enqueue(ServerProcolCommand.Handshake_ClientFinished);
        }

        private void ServerHelloNotPsk()
        {
            // full crypto (not PSK), select: ciphersuite, (ec)dhe group, signature algorithm

            bool isClientHello1 = context.ClientHello2 == null;
            ClientHello clientHello = context.ClientHello2 ?? context.ClientHello1;

            if (isClientHello1)
            {
                bool groupOk, cipherSuiteOk, signAlgoOk;
                crypto.SelectSuiteAndEcEcdheGroupAndSigAlgo(context.ClientHello1, out groupOk, out cipherSuiteOk, out signAlgoOk);
                validate.Handshake.SelectedSuiteAndEcEcdheGroupAndSignAlgo(groupOk, cipherSuiteOk, signAlgoOk);
            }

            // todo validate if set on ch2
            var keyShare = clientHello.GetExtension<KeyShareClientHelloExtension>(ExtensionType.KeyShare)
                .ClientShares
                .FirstOrDefault(share => share.NamedGroup == crypto.SelectedNamedGroup);

            List<Extension> extensions = new List<Extension>()
            {
                ServerSupportedVersionsExtension.ServerHelloTls13, //todo uncomment
            };

            ServerHello serverHello;
            var random = new byte[Tls13Const.HelloRandomFieldLength];

            if (isClientHello1)
            {
                // random randomgeneratr
            }
            else
            {
                MemOps.MemsetZero(random);
            }

            serverHello = new ServerHello(random,
                    context.ClientHello1.LegacySessionId,
                    crypto.SelectedCipherSuite,
                    extensions);

            if (keyShare == null)
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
            else
            {
                var keyShareToSend = crypto.GenerateSharedSecretAndGetKeyShareToSend(keyShare);
                extensions.Add(new KeyShareServerHelloExtension(new KeyShareEntry(crypto.SelectedNamedGroup, keyShareToSend)));
            }
            
            messageIO.WriteHandshake(serverHello);

            crypto.InitEarlySecret(handshakeContext);
            crypto.InitHandshakeSecret(handshakeContext);

            messageIO.ChangeRecordLayerCrypto(crypto, Crypto.RecordLayerKeyType.Handshake);

            CommandQueue.Enqueue(ServerProcolCommand.Handshake_EncryptedExtensions);
            CommandQueue.Enqueue(ServerProcolCommand.Handshake_ServerCertificate);
            CommandQueue.Enqueue(ServerProcolCommand.Handshake_ServerCertificateVerify);
            CommandQueue.Enqueue(ServerProcolCommand.Handshake_ServerFinished);
            CommandQueue.Enqueue(ServerProcolCommand.Handshake_ClientFinished);
        }

        private void FirstClientHello()
        {
            messageIO.SetBackwardCompatibilityMode(
                compatibilityAllowRecordLayerVersionLower0x0303: true,
                compatibilitySilentlyDropUnencryptedChangeCipherSpec: false);

            CommandQueue.Enqueue(ServerProcolCommand.Handshake_ClientHello1);
        }

        static void test()
        {
            string s = @"02 00 00 ac 03 03 cf 21 ad 74 e5 9a 61
         11 be 1d 8c 02 1e 65 b8 91 c2 a2 11 16 7a bb 8c 5e 07 9e 09 e2
         c8 a8 33 9c 00 13 01 00 00 84 00 33 00 02 00 17 00 2c 00 74 00
         72 71 dc d0 4b b8 8b c3 18 91 19 39 8a 00 00 00 00 ee fa fc 76
         c1 46 b8 23 b0 96 f8 aa ca d3 65 dd 00 30 95 3f 4e df 62 56 36
         e5 f2 1b b2 e2 3f cc 65 4b 1b 5b 40 31 8d 10 d1 37 ab cb b8 75
         74 e3 6e 8a 1f 02 5f 7d fa 5d 6e 50 78 1b 5e da 4a a1 5b 0c 8b
         e7 78 25 7d 16 aa 30 30 e9 e7 84 1d d9 e4 c0 34 22 67 e8 ca 0c
         af 57 1f b2 b7 cf f0 f9 34 b0 00 2b 00 02 03 04".Replace(" ", "").Replace("\r\n", "");
            var b = BinConverter.FromString(s);

            (new ModelDeserialization(new Validate())).Deserialize<ServerHello>(b, 0);
        }

        private void ClientHello1()
        {
            // test();

            ClientHello clientHello = messageIO.LoadHandshakeMessage<ClientHello>();
            validate.ClientHello.GeneralValidateClientHello(clientHello);

            // todo: if clientkeyshare didn't send crypto arguments need to helloretryrequest

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
