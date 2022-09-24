using Arctium.Connection.Tls.Tls13.API;
using Arctium.Connection.Tls.Tls13.Model;
using Arctium.Connection.Tls.Tls13.Model.Extensions;
using Arctium.Shared;
using Arctium.Shared.Exceptions;
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
            //messageIO.TryLoadApplicationData(applicationDataBuffer, 0, out applicationDataLength);
            //CommandQueue.Enqueue(ServerProcolCommand.Handshake_ServerFinished);
        }

        private void ServerCertificate()
        {
            var certificate = new Certificate(new byte[0], new CertificateEntry[]
            {
                new CertificateEntry(CertificateType.X509, config.DerEncodedCertificateBytes, new Extension[0])
            });

            messageIO.WriteHandshake(certificate);
            //messageIO.recordLayer.Read();
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
                }
                else if (keyExchangeModes.Contains(PreSharedKeyExchangeModeExtension.PskKeyExchangeMode.PskKe))
                {
                    crypto.SelectCipherSuite(clientHello, out cipherOk);
                    groupOk = true;
                }
                else validate.Handshake.AlertFatal(true, AlertDescription.Illegal_parameter, "keyExchangeModes not supported or illegal param");

                validate.Handshake.AlertFatal(!(cipherOk && groupOk), AlertDescription.HandshakeFailure, "client and server ececdhe or cipher suites does not match mutually");
            }
            else
            {
                helloRetryNeeded = false;
            }

            if (helloRetryNeeded)
            {
                throw new NotImplementedException();
                // send retry and go back to this method again
                // helloretry = new serverhello(...)
                // messageio.write(helloretry);
                // CommandQueue.Enqueue(ServerProcolCommand.Handshake_SendHelloRetryRequestAndLoadClientHello2);
                // CommandQueue.Enqueue(ServerProcolCommand.Handshake_ServerHelloPsk);
            }

            if (!isClientHello1)
            {
                throw new NotImplementedException();
                // build serverhello based on retry if needed or some params must be same
            }

            

            var random = new byte[Tls13Const.HelloRandomFieldLength];

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

            var extensions = new List<Extension>
            {
                ServerSupportedVersionsExtension.ServerHelloTls13,
                new PreSharedKeyServerHelloExtension((ushort)selectedClientIdentity),
                // not send keyshare?
            };

            // TODO what to do with retry request? how this works
            if (helloRetryNeeded)
            {
                extensions.Add(new KeyShareHelloRetryRequestExtension(crypto.SelectedNamedGroup));
            }
            else
            {
                var keyShareToSend = crypto.GenerateSharedSecretAndGetKeyShareToSend(clientKeyShare);
                extensions.Add(new KeyShareServerHelloExtension(new KeyShareEntry(crypto.SelectedNamedGroup, keyShareToSend)));
            }

            crypto.SetupPsk(pskTicket.ResumptionMasterSecret, pskTicket.TicketNonce);
            crypto.InitEarlySecret(handshakeContext);

            byte[] binderValue = crypto.ComputePskBinderValue(handshakeContext);

            validate.Handshake.AlertFatal(!MemOps.Memcmp(binderValue, preSharedKeyExtension.Binders[selectedClientIdentity]),
                AlertDescription.DecryptError, "binder value invalid");


            ServerHello serverHello = new ServerHello(random, context.ClientHello1.LegacySessionId, crypto.SelectedCipherSuite, extensions.ToArray());

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

            if (!isClientHello1)
            {
                throw new NotImplementedException("");
            }

            bool groupOk, cipherSuiteOk, signAlgoOk;
            crypto.SelectSuiteAndEcEcdheGroupAndSigAlgo(context.ClientHello1, out groupOk, out cipherSuiteOk, out signAlgoOk);
            validate.Handshake.SelectedSuiteAndEcEcdheGroupAndSignAlgo(groupOk, cipherSuiteOk, signAlgoOk);

            var keyShare = context.ClientHello1.GetExtension<KeyShareClientHelloExtension>(ExtensionType.KeyShare)
                .ClientShares
                .Single(share => share.NamedGroup == crypto.SelectedNamedGroup);

            var random = new byte[Tls13Const.HelloRandomFieldLength];
            var keyShareToSend = crypto.GenerateSharedSecretAndGetKeyShareToSend(keyShare);

            var extensions = new Extension[]
            {
                ServerSupportedVersionsExtension.ServerHelloTls13,
                new KeyShareServerHelloExtension(new KeyShareEntry(crypto.SelectedNamedGroup, keyShareToSend))
            };

            ServerHello serverHello = new ServerHello(random, context.ClientHello1.LegacySessionId, crypto.SelectedCipherSuite, extensions);

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

        private void ClientHello1()
        {
            ClientHello clientHello = messageIO.LoadHandshakeMessage<ClientHello>();
            validate.ClientHello.GeneralValidateClientHello(clientHello);

            // todo: if clientkeyshare didn't send crypto arguments need to helloretryrequest

            context.ClientHello1 = clientHello;
            PreSharedKeyClientHelloExtension _;

            if (false && clientHello.TryGetExtension<PreSharedKeyClientHelloExtension>(ExtensionType.PreSharedKey, out _))
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
