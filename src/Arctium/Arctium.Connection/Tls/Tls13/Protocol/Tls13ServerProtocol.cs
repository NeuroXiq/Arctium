using Arctium.Connection.Tls.Tls13.API;
using Arctium.Connection.Tls.Tls13.Model;
using Arctium.Connection.Tls.Tls13.Model.Extensions;
using Arctium.Shared;
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
        }

        private byte[] applicationDataBuffer = new byte[Tls13Const.RecordLayer_MaxPlaintextApplicationDataLength];
        private int applicationDataLength;

        private ServerProcolCommand Command;
        private ServerProtocolState State;
        private MessageIO messageIO;
        private Crypto crypto;
        private Validate validate;
        private List<KeyValuePair<HandshakeType, byte[]>> handshakeContext;
        private Context context;
        private Tls13ServerConfig config;

        public Tls13ServerProtocol(Stream networkStream, Tls13ServerConfig config)
        {
            this.config = config;
            validate = new Validate();
            handshakeContext = new List<KeyValuePair<HandshakeType, byte[]>>();
            messageIO = new MessageIO(networkStream, validate, handshakeContext);
            crypto = new Crypto(Endpoint.Server, config);
            context = new Context();
            applicationDataLength = 0;
        }

        public void Listen()
        {
            Command = ServerProcolCommand.Start;
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
            Command = ServerProcolCommand.LoadApplicationData;

            ProcessCommandLoop();
        }

        void ProcessCommandLoop()
        {
            while (Command != ServerProcolCommand.BreakLoopWaitForOtherCommand)
            {
                switch (State)
                {
                    case ServerProtocolState.Listen: ListenState(); break;
                    case ServerProtocolState.Handshake: HandshakeState();  break;
                    case ServerProtocolState.Connected: ConnectedState();  break;
                    default: throw new Tls13Exception("internal: invalid state");
                }
            }
        }

        private void ListenState()
        {
            if (Command != ServerProcolCommand.Start) throw new Tls13Exception("Command not valid for this state");

            State = ServerProtocolState.Handshake;
            Command = ServerProcolCommand.FirstClientHello;
        }

        private void ConnectedState()
        {
            switch (Command)
            {
                case ServerProcolCommand.LoadApplicationData: LoadApplicationData(); break;
                case ServerProcolCommand.LoadApplicationDataNotReceivedApplicationDataContent: LoadApplicationDataNotReceivedApplicationDataContent(); break;
                default: throw new NotImplementedException("connected");
            }
        }

        private void HandshakeState()
        {
            switch (Command)
            {
                case ServerProcolCommand.FirstClientHello: FirstClientHello(); break;
                case ServerProcolCommand.ClientHello: ClientHello(); break;
                case ServerProcolCommand.ServerHelloNotPsk: ServerHelloNotPsk();  break;
                case ServerProcolCommand.ServerHelloPsk: ServerHelloPsk(); break;
                case ServerProcolCommand.EncryptedExtensions: EncryptedExtensions(); break;
                case ServerProcolCommand.ServerCertificate: ServerCertificate();  break;
                case ServerProcolCommand.ServerCertificateVerify: ServerCertificateVerify();  break;
                case ServerProcolCommand.ServerFinished: ServerFinished(); break;
                case ServerProcolCommand.ClientFinished: ClientFinished(); break;
                case ServerProcolCommand.CertificateRequest:
                case ServerProcolCommand.ClientCertificate:
                case ServerProcolCommand.ClientCertificateVerify:
                default: throw new Tls13Exception("command not valid for this state");
            }
        }

        private void LoadApplicationDataNotReceivedApplicationDataContent()
        {
            throw new NotImplementedException();
        }

        private void LoadApplicationData()
        {
            if (messageIO.TryLoadApplicationData(applicationDataBuffer, 0, out applicationDataLength))
            {
                Command = ServerProcolCommand.BreakLoopWaitForOtherCommand;
            }
            else
            {
                Command = ServerProcolCommand.LoadApplicationDataNotReceivedApplicationDataContent;
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

            State = ServerProtocolState.Connected;
            Command = ServerProcolCommand.BreakLoopWaitForOtherCommand;
        }

        private void ServerFinished()
        {
            var finishedVerifyData = crypto.ServerFinished(handshakeContext.Select(x => x.Value).ToList());
            var finished = new Finished(finishedVerifyData);

            messageIO.WriteHandshake(finished);

            // todo: or get certificate from client if needed

            Command = ServerProcolCommand.ClientFinished;
        }

        private void ServerCertificateVerify()
        {
            var signature = crypto.GenerateServerCertificateVerifySignature(handshakeContext);

            var certificateVerify = new CertificateVerify(crypto.SelectedSignatureScheme, signature);

            messageIO.WriteHandshake(certificateVerify);

            Command = ServerProcolCommand.ServerFinished;
        }

        private void ServerCertificate()
        {
            var certificate = new Certificate(new byte[0], new CertificateEntry[]
            {
                new CertificateEntry(CertificateType.X509, config.DerEncodedCertificateBytes, new Extension[0])
            });

            messageIO.WriteHandshake(certificate);

            Command = ServerProcolCommand.ServerCertificateVerify;
        }

        private void EncryptedExtensions()
        {
            Extension[] extensions = new Extension[]
            {
                new ProtocolNameListExtension(new byte[][] { System.Text.Encoding.ASCII.GetBytes("http/1.1") })
            };

            var encryptedExtensions = new EncryptedExtensions(extensions);

            messageIO.WriteHandshake(encryptedExtensions);

            Command = ServerProcolCommand.ServerCertificate;
        }

        private void ServerHelloPsk()
        {
            throw new NotImplementedException();

            Command = ServerProcolCommand.EncryptedExtensions;
        }

        private void ServerHelloNotPsk()
        {
            // full crypto (not PSK), select: ciphersuite, (ec)dhe group, signature algorithm

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

            crypto.InitEarlySecret(handshakeContext[0].Value);
            crypto.InitHandshakeSecret(handshakeContext.Take(2).Select(c => c.Value).ToList());

            messageIO.ChangeRecordLayerCrypto(crypto, Crypto.RecordLayerKeyType.Handshake);

            Command = ServerProcolCommand.EncryptedExtensions;
        }

        private void FirstClientHello()
        {
            // messageIO.SetState(MessageIOState.FirstClientHello);
            messageIO.SetBackwardCompatibilityMode(
                compatibilityAllowRecordLayerVersionLower0x0303: true,
                compatibilitySilentlyDropUnencryptedChangeCipherSpec: false);

            Command = ServerProcolCommand.ClientHello;
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

            bool groupOk, cipherSuiteOk, signAlgoOk;
            crypto.SelectSuiteAndEcEcdheGroupAndSigAlgo(clientHello, out groupOk, out cipherSuiteOk, out signAlgoOk);
            validate.Handshake.SelectedSuiteAndEcEcdheGroupAndSignAlgo(groupOk, cipherSuiteOk, signAlgoOk);

            context.ClientHello = clientHello;

            messageIO.SetBackwardCompatibilityMode(
                compatibilityAllowRecordLayerVersionLower0x0303: false,
                compatibilitySilentlyDropUnencryptedChangeCipherSpec: true);

            Command = ServerProcolCommand.ServerHelloNotPsk;
        }
    }
}
