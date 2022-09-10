using Arctium.Connection.Tls.Tls13.API;
using Arctium.Connection.Tls.Tls13.Model;
using Arctium.Connection.Tls.Tls13.Model.Extensions;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Arctium.Connection.Tls.Tls13.Protocol
{
    class Tls13ServerProtocol
    {
        class Context
        {
            //public ClientHello ClientHello;
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

        private ServerProcolCommand Command;
        private ServerProtocolState State;
        private MessageIO messageIO;
        private Crypto crypto;
        private Validate validate;
        private List<KeyValuePair<HandshakeType, byte[]>> handshakeContext;

        public Tls13ServerProtocol(Stream networkStream, Tls13ServerConfig config)
        {
            handshakeContext = new List<KeyValuePair<HandshakeType, byte[]>>();
            messageIO = new MessageIO(networkStream, validate, handshakeContext);
            crypto = new Crypto(Endpoint.Server);
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

        public void ConnectedState()
        {
            switch (Command)
            {
                default: throw new NotImplementedException();
            }
        }

        private void HandshakeState()
        {
            switch (Command)
            {
                case ServerProcolCommand.FirstClientHello: FirstClientHello(); break;
                case ServerProcolCommand.ClientHello: ClientHello(); break;
                case ServerProcolCommand.ServerHello:
                    break;
                case ServerProcolCommand.EncryptedExtensions:
                    break;
                case ServerProcolCommand.CertificateRequest:
                    break;
                case ServerProcolCommand.ServerCertificate:
                    break;
                case ServerProcolCommand.ServerCertificateVerify:
                    break;
                case ServerProcolCommand.ServerFinished:
                    break;
                case ServerProcolCommand.ClientCertificate:
                    break;
                case ServerProcolCommand.ClientCertificateVerify:
                    break;
                default: throw new Tls13Exception("command not valid for this state");
            }
        }

        private void FirstClientHello()
        {
            messageIO.SetState(MessageIOState.FirstClientHello);

            Command = ServerProcolCommand.ClientHello;
        }

        private void ClientHello()
        {
            ClientHello clientHello = messageIO.LoadHandshakeMessage<ClientHello>();

            // select cipher suite
            int i = 0;
            for (; i < crypto.SupportedCipherSuites.Count; i++)
                for (int j = 0; j < clientHello.CipherSuites.Length; j++)
                    if (clientHello.CipherSuites[j] == crypto.SupportedCipherSuites[i]) break;

            validate.Handshake.CipherSuitesNotOverlapWithSupported(i == crypto.SupportedCipherSuites.Count);
            validate.ClientHello.GeneralValidateClientHello(clientHello);

            // select supported groups
            var clientKeyShare = clientHello.GetExtension<KeyShareClientHelloExtension>(ExtensionType.KeyShare);

            var x255group = clientHello.GetExtension<SupportedGroupExtension>(ExtensionType.SupportedGroups)
                .NamedGroupList
                .Any(g => g == SupportedGroupExtension.NamedGroup.X25519);

            var x255 = clientKeyShare.ClientShares.FirstOrDefault(share => share.NamedGroup == SupportedGroupExtension.NamedGroup.X25519);

            validate.Handshake.ClientSupportedGroupsNotOverlapWithImplemented(!x255group);
            validate.Handshake.ThrowGeneral(x255 != null, "internal not impl. helloretryrequest to implement");

            // select signature algorithm


            this.messageIO.SetState(MessageIOState.AfterFirstClientHello);
            Command = ServerProcolCommand.ServerHello;
        }
    }
}
