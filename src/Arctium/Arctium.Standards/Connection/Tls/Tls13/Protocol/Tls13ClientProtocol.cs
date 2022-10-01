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
        class Context
        {
            public ClientHello ClientHello1;
            public ClientHello ClientHello2;
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

        public Tls13ClientProtocol(Stream networkRawStream, Tls13ClientConfig config)
        {
            this.config = config;
            this.context = new Context();
            this.crypto = new Crypto(Endpoint.Client, null);
            validate = new Validate();
            hscontext = new HandshakeContext();
            messageIO = new MessageIO(networkRawStream, validate, hscontext);

            commandQueue = new Queue<ClientProtocolCommand>();
        }

        public void Connect()
        {
            commandQueue.Enqueue(ClientProtocolCommand.Start_Connect);

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
                    case ClientProtocolState.Closed: throw new Tls13Exception("Cannot process command because connection is closed"); break;
                    case ClientProtocolState.FatalError: throw new Tls13Exception("Cannot process command because encountered fatal error"); break;
                    default: Validation.ThrowInternal(); break;
                }
            }
        }

        private void Connected()
        {
            throw new NotImplementedException();
        }

        private void Start()
        {
            switch (currentCommand)
            {
                case ClientProtocolCommand.Start_Connect: Start_Connect(); break;
                default: throw new Tls13Exception("command invalid for this state");
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
                default: throw new Tls13Exception("invalid command for this state"); break;
            }
        }

        private void Handshake_ClientFinished()
        {
            throw new NotImplementedException();
        }

        private void Handshake_ClientCertificateVerify()
        {
            throw new NotImplementedException();
        }

        private void Handshake_ClientCertificate()
        {
            throw new NotImplementedException();
        }

        private void Handshake_ServerFinished()
        {
            throw new NotImplementedException();
        }

        private void Handshake_ServerCertificateVerify()
        {
            throw new NotImplementedException();
        }

        private void Handshake_ServerCertificate()
        {
            throw new NotImplementedException();
        }

        private void Handshake_CertificateRequest()
        {
            throw new NotImplementedException();
        }

        private void Handshake_EncryptedExtensions()
        {
            throw new NotImplementedException();
        }

        private void Handshake_ServerHello()
        {
            var sh = messageIO.LoadHandshakeMessage<ServerHello>();

            if (MemOps.Memcmp(sh.Random, ServerHello.RandomSpecialConstHelloRetryRequest))
            {
                // hello retry request
                throw new Exception();
                commandQueue.Enqueue(ClientProtocolCommand.Handshake_ClientHello);
                return;
            }

            var x = "";
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
                new ClientSupportedVersionsExtension(new ushort[] { Tls13Const.Tls13VersionUShort }),
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
                }));
            }

            var clientHello = new ClientHello(random, sesId, suites, extensions);
            messageIO.WriteHandshake(clientHello);

            commandQueue.Enqueue(ClientProtocolCommand.Handshake_ServerHello);
        }

        private void Start_Connect()
        {
            state = ClientProtocolState.Handshake;
            commandQueue.Enqueue(ClientProtocolCommand.Handshake_ClientHello);
        }
    }
}
