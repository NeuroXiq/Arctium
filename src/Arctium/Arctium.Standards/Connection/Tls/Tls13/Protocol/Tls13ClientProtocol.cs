/*
 *  TLS 1.3 Client implementation
 *  Implemented by NeuroXiq 2022
 */

// todo tls13 free memory after connected success

using Arctium.Shared;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Shared.Other;
// using Arctium.Standards.Connection.Tls.Tls13.API;
using Arctium.Standards.Connection.Tls.Tls13.Model;
using Arctium.Standards.Connection.Tls.Tls13.Model.Extensions;
using Arctium.Standards.X509.X509Cert;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Arctium.Standards.Connection.Tls.Tls13.Protocol
{
    internal class Tls13ClientProtocol
    {
        public struct ConnectedInfo
        {
            public bool IsPskSessionResumption;
            public byte[][] ServerCertificates;
            public SupportedGroupExtension.NamedGroup? KeyExchangeNamedGroup;
            public SignatureSchemeListExtension.SignatureScheme? ServerCertificateVerifySignatureScheme;
            public CipherSuite CipherSuite;
            public bool ServerRequestedCertificateInHandshake;
            public ushort? NegotiatedRecordSizeLimitExtension;
            public byte[] ExtensionResultALPN;
            public bool ExtensionResultServerName;
        }

        public byte[] ApplicationDataBuffer { get; private set; }
        public int ApplicationDataLength { get { return applicationDataLength; } }

        class Context
        {
            public ClientHello ClientHello1;
            public ServerHello HelloRetryRequest;
            public ClientHello ClientHello2;
            public bool ServerRequestedCertificateInHandshake;
            public X509.X509Cert.X509Certificate ServerCertificate;

            public API.PskTicket[] PskTickets;
            public ServerHello ServerHello;

            public int CH1Length = -1;
            public bool IsPskSessionResumption;

            public byte[][] ServerCertificatesRawBytes { get; internal set; }
            public ushort? NegotiatedRecordSizeLimitExtension { get; internal set; }

            public SignatureSchemeListExtension.SignatureScheme? ServerCertificateVerifySignatureScheme;
            public SupportedGroupExtension.NamedGroup? KeyExchangeNamedGroup;
            public byte[] ExtensionALPN_ProtocolSelectedByServer;
            public bool ExtensionServerNameList_ReceivedFromServer;
        }

        Context context;
        API.Tls13ClientConfig config { get { return clientContext.Config; } }
        ClientProtocolState state;
        Queue<ClientProtocolCommand> commandQueue;
        Crypto crypto;
        Dictionary<SupportedGroupExtension.NamedGroup, byte[]>  generatedPrivateKeys;
        MessageIO messageIO;
        Validate validate;
        ClientProtocolCommand currentCommand;
        API.Tls13ClientContext clientContext;
        ByteBuffer hsctx;

        byte[] writeApplicationDataBuffer;
        long writeApplicationDataOffset;
        long writeApplicationDataLength;
        int applicationDataLength;

        public Tls13ClientProtocol(Stream networkRawStream, API.Tls13ClientContext clientContext)
        {
            this.clientContext = clientContext;
            this.context = new Context();
            this.crypto = new Crypto(Endpoint.Client, null);
            this.generatedPrivateKeys = new Dictionary<SupportedGroupExtension.NamedGroup, byte[]>();
            hsctx = new ByteBuffer();
            validate = new Validate();
            messageIO = new MessageIO(networkRawStream, validate);
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

        public ConnectedInfo Connect()
        {
            commandQueue.Enqueue(ClientProtocolCommand.Start_Connect);

            ProcessCommand();

            var info = new ConnectedInfo
            {
                IsPskSessionResumption = context.IsPskSessionResumption,
                ServerCertificates = context.ServerCertificatesRawBytes,
                KeyExchangeNamedGroup = context.KeyExchangeNamedGroup,
                CipherSuite = crypto.SelectedCipherSuite,
                ServerCertificateVerifySignatureScheme = context.ServerCertificateVerifySignatureScheme,
                ServerRequestedCertificateInHandshake = context.ServerRequestedCertificateInHandshake,
                NegotiatedRecordSizeLimitExtension = context.NegotiatedRecordSizeLimitExtension,
                ExtensionResultALPN = context.ExtensionALPN_ProtocolSelectedByServer,
                ExtensionResultServerName = context.ExtensionServerNameList_ReceivedFromServer,
            };

            return info;
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
                    case ClientProtocolState.Closed: ThrowEx("Cannot process command because connection is closed"); break;
                    case ClientProtocolState.FatalError: ThrowEx("Cannot process command because encountered fatal error"); break;
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
                default: ThrowEx("invalid operation for this state"); break;
            }
        }

        private void Start()
        {
            switch (currentCommand)
            {
                case ClientProtocolCommand.Start_Connect: Start_Connect(); break;
                default: ThrowEx("command invalid for this state"); break;
            }
        }

        private void PostHandshake()
        {
            switch (currentCommand)
            {
                case ClientProtocolCommand.PostHandshake_ProcessPostHandshakeMessage: PostHandshake_ProcessPostHandshakeMessage(); break;
                case ClientProtocolCommand.PostHandshake_FinishedProcessingPostHandshakeMessages: PostHandshake_FinishedProcessingPostHandshakeMessages(); break;
                default: ThrowEx("inavlid command for this state"); break;
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
                default: ThrowEx("invalid command for this state"); break;
            }
        }

        private void ThrowEx(string msg)
        {
            throw new API.Tls13Exception(msg); 
            
        }

        public void LoadApplicationData() => ProcessCommand(ClientProtocolCommand.Connected_ReadApplicationData);

        public void WriteApplicationData(byte[] buffer, long offset, long length)
        {
            writeApplicationDataBuffer = buffer;
            writeApplicationDataOffset = offset;
            writeApplicationDataLength = length;

            ProcessCommand(ClientProtocolCommand.Connected_WriteApplicationData);

            // free memory (do not lock buffer from external source)
            writeApplicationDataBuffer = null;
            writeApplicationDataOffset = -1;
            writeApplicationDataLength = -1;
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
        }

        private void Handshake_ClientFinished()
        {
            var finishedVerData = crypto.ComputeFinishedVerData(hsctx, Endpoint.Client);
            var finished = new Finished(finishedVerData);

            crypto.SetupMasterSecret(hsctx);
            messageIO.WriteHandshake(finished);
            crypto.SetupResumptionMasterSecret(hsctx);

            messageIO.ChangeRecordLayerCrypto(crypto, Crypto.RecordLayerKeyType.ApplicationData);
            messageIO.OnHandshakeReadWrite -= MessageIO_OnHandshakeReadWrite;
            messageIO.SetBackwardCompatibilityMode(false, false);

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
            // todo verify finished

            if (context.ServerRequestedCertificateInHandshake) commandQueue.Enqueue(ClientProtocolCommand.Handshake_ClientCertificate);
            else commandQueue.Enqueue(ClientProtocolCommand.Handshake_ClientFinished);
        }

        private void Handshake_ServerCertificateVerify()
        {
            int dataLengthToSign = hsctx.DataLength;
            var certVerify = messageIO.ReadHandshakeMessage<CertificateVerify>();
            context.ServerCertificateVerifySignatureScheme = certVerify.SignatureScheme;

            bool isSignatureValid = crypto.IsServerCertificateVerifyValid(hsctx.Buffer, dataLengthToSign, certVerify, context.ServerCertificate);

            validate.Handshake.AlertFatal(!isSignatureValid, AlertDescription.DecryptError, "invalid servercertificateverify signature");

            commandQueue.Enqueue(ClientProtocolCommand.Handshake_ServerFinished);
        }

        private void Handshake_ServerCertificate()
        {
            var certificate = messageIO.ReadHandshakeMessage<Certificate>();
            var x509PathRawBytes = certificate.CertificateList.Select(entry => entry.CertificateEntryRawBytes).ToArray();
            context.ServerCertificatesRawBytes = x509PathRawBytes;

            try
            {
                X509CertificateDeserializer deserialized = new X509CertificateDeserializer();
                context.ServerCertificate = deserialized.FromBytes(certificate.CertificateList[0].CertificateEntryRawBytes);
            }
            catch (Exception e)
            {
                validate.Certificate.AlertFatal(true, AlertDescription.BadCertificate, "cannot deserialize certificate. Maybe invalid certificate or not suppored deserialization by Arctium lib.");
            }

            if (config.X509CertificateValidationCallback != null)
            {
                var validationResult = config.X509CertificateValidationCallback(x509PathRawBytes);
                validate.Certificate.ValidateCertificateValidationCallbackSuccess(validationResult);
            }
            

            commandQueue.Enqueue(ClientProtocolCommand.Handshake_ServerCertificateVerify);
        }

        private void Handshake_CertificateRequest()
        {
            // var certReq = messageIO.ReadHandshakeMessage<CertificateRequest>();

            commandQueue.Enqueue(ClientProtocolCommand.Handshake_ServerCertificate);
        }

        private void Handshake_EncryptedExtensions()
        {
            var encryptedExt = messageIO.ReadHandshakeMessage<EncryptedExtensions>();
            validate.EncryptedExtensions.General(encryptedExt, context.ClientHello1 ?? context.ClientHello1);


            // Extension: Record Size Limit
            var recordSizeLimitFromServer = encryptedExt.Extensions.FirstOrDefault(ext => ext.ExtensionType == ExtensionType.RecordSizeLimit) as RecordSizeLimitExtension;
            bool didClientSendRecordSizeLimit = config.ExtensionRecordSizeLimit.HasValue;

            if (didClientSendRecordSizeLimit && recordSizeLimitFromServer != null)
            {
                // todo tls13 not sure if this is correct (condition in if for this block), can server send recordsizelimit if client did not?
                ushort min = Math.Min(config.ExtensionRecordSizeLimit.Value, recordSizeLimitFromServer.RecordSizeLimit);
                context.NegotiatedRecordSizeLimitExtension = min;
                messageIO.SetRecordSizeLimit(min);
            }

            // Extension: server name list
            context.ExtensionServerNameList_ReceivedFromServer = encryptedExt.Extensions.Any(e => e.ExtensionType == ExtensionType.ServerName);

            // Extension: alpn
            var alpnServer = encryptedExt.Extensions.FirstOrDefault(e => e.ExtensionType == ExtensionType.ApplicationLayerProtocolNegotiation) as ProtocolNameListExtension;

            if (alpnServer != null)
            {
                context.ExtensionALPN_ProtocolSelectedByServer = alpnServer.ProtocolNamesList[0];
            }

            if (context.IsPskSessionResumption) commandQueue.Enqueue(ClientProtocolCommand.Handshake_ServerFinished);
            else if (messageIO.LoadHandshakeMessage() == HandshakeType.CertificateRequest)
            {
                context.ServerRequestedCertificateInHandshake = true;
                commandQueue.Enqueue(ClientProtocolCommand.Handshake_CertificateRequest);
            }
            else
            {
                context.ServerRequestedCertificateInHandshake = false;
                commandQueue.Enqueue(ClientProtocolCommand.Handshake_ServerCertificate);
            }
        }

        private void Handshake_ServerHello()
        {
            bool onHelloRetry = context.HelloRetryRequest != null;
            var sh = context.ServerHello;

            validate.ServerHello.GeneralServerHelloValidate(context.ClientHello2, sh);

            var serverKeyShare = ((KeyShareServerHelloExtension)sh.Extensions.Find(e => e.ExtensionType == ExtensionType.KeyShare)).ServerShare;
            var preSharedKeySh = sh.Extensions.FirstOrDefault(ext => ext.ExtensionType == ExtensionType.PreSharedKey) as PreSharedKeyServerHelloExtension;
            byte[] psk = null;

            if (!onHelloRetry) crypto.SelectCipherSuite(sh.CipherSuite);

            // todo check if server response is correct compared to sended CH (check if this class send keyexchangemode.psk_ke)
            // todo server could select KeyExchangeMode_ke (not dhe), need to implement this
            if (serverKeyShare == null) throw new InvalidOperationException();
            else
            {
                context.KeyExchangeNamedGroup = serverKeyShare.NamedGroup;
                crypto.ComputeSharedSecret(serverKeyShare.NamedGroup, this.generatedPrivateKeys[serverKeyShare.NamedGroup], serverKeyShare.KeyExchangeRawBytes);
            }

            if (preSharedKeySh != null)
            {
                validate.ServerHello.AlertFatal(preSharedKeySh.SelectedIdentity >= context.PskTickets.Length, AlertDescription.Illegal_parameter, "server send selected identity out of range");
                var ticket = context.PskTickets[preSharedKeySh.SelectedIdentity];
                psk = crypto.GeneratePsk(ticket.ResumptionMasterSecret, ticket.TicketNonce);
                context.IsPskSessionResumption = true;
            }

            crypto.SetupEarlySecret(psk);
            crypto.SetupHandshakeSecret(hsctx);

            messageIO.ChangeRecordLayerCrypto(crypto, Crypto.RecordLayerKeyType.Handshake);

            commandQueue.Enqueue(ClientProtocolCommand.Handshake_EncryptedExtensions);
        }

        private void Handshake_ClientHello2()
        {
            // process HelloRetryRequst
            // 1. send everything what was send in clienthello1 (but skip 'key share' sended in clienthello1 because server selected, this is reason of this situation here)
            // 2. get keyshareserverhelloretry from server and send key share which server wants

            validate.HelloRetryRequest.GeneralValidate(context.ClientHello1, context.HelloRetryRequest);
            crypto.SelectCipherSuite(context.HelloRetryRequest.CipherSuite);
            crypto.ReplaceClientHello1WithMessageHash(hsctx, context.CH1Length);

            var extensions2 = new List<Extension>();
            var serverKeyShare = (KeyShareHelloRetryRequestExtension)context.HelloRetryRequest.Extensions.First(ext => ext.ExtensionType == ExtensionType.KeyShare);
            byte[] keyShareToSendRawBytes, privateKey;

            crypto.GeneratePrivateKeyAndKeyShareToSend(serverKeyShare.SelectedGroup, out keyShareToSendRawBytes, out privateKey);
            generatedPrivateKeys[serverKeyShare.SelectedGroup] = privateKey;

            foreach (var extensionInCH1 in context.ClientHello1.Extensions)
            {
                // skip keyshare from ch1.
                // Skip presharedkey because this is implemented here in a way that method 'appendlstextensionpresharedkey' must be called last
                if (extensionInCH1.ExtensionType == ExtensionType.KeyShare ||
                    extensionInCH1.ExtensionType == ExtensionType.PreSharedKey)
                    continue;

                extensions2.Add(extensionInCH1);
            }

            var cookieFromServer = context.HelloRetryRequest.Extensions.FirstOrDefault(e => e.ExtensionType == ExtensionType.Cookie) as CookieExtension;
            if (cookieFromServer != null)
            {
                extensions2.Add(cookieFromServer);
            }

            extensions2.Add(new KeyShareClientHelloExtension(new KeyShareEntry[] { new KeyShareEntry(serverKeyShare.SelectedGroup, keyShareToSendRawBytes) }));

            context.ClientHello2 = new ClientHello(context.ClientHello1.Random,
                context.ClientHello1.LegacySessionId,
                context.ClientHello1.CipherSuites,
                extensions2);

            AppendLastExtensionPreSharedKey(context.ClientHello2);
            messageIO.WriteHandshake(context.ClientHello2);
            
            commandQueue.Enqueue(ClientProtocolCommand.Handshake_ServerHelloOrHelloRetryRequest);
        }

        private void AppendLastExtensionPreSharedKey(ClientHello clientHello)
        {
            PreSharedKeyClientHelloExtension preSharedKeyExtension;

            context.PskTickets = clientContext.GetPskTickets();
            
            if (context.PskTickets.Length == 0) return;

            var identities = new List<PreSharedKeyClientHelloExtension.PskIdentity>();
            List<byte[]> binders = new List<byte[]>();

            foreach (var ticket in context.PskTickets)
            {
                uint obfustatedTicketAge = ticket.TicketLifetime + ticket.TicketAgeAdd;
                identities.Add(new PreSharedKeyClientHelloExtension.PskIdentity(ticket.Ticket, obfustatedTicketAge));

                binders.Add(new byte[crypto.GetHashSizeInBytes(ticket.HashFunctionId)]);
            }
            preSharedKeyExtension = new PreSharedKeyClientHelloExtension(identities.ToArray(), binders.ToArray());
            clientHello.Extensions.Add(preSharedKeyExtension);

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

            messageIO.SetBackwardCompatibilityMode(compatibilityAllowRecordLayerVersionLower0x0303: false,
                compatibilitySilentlyDropUnencryptedChangeCipherSpec: true);
        }

        private void Handshake_ClientHello1()
        {
            var random = new byte[Tls13Const.HelloRandomFieldLength];
            byte[] sesId = new byte[Tls13Const.ClientHello_LegacySessionIdMaxLen];
            CipherSuite[] suites = config.CipherSuites;
            List<KeyShareEntry> generatedKeysToExchange = new List<KeyShareEntry>();
            ClientHello clientHello;

            GlobalConfig.RandomGeneratorCryptSecure(random, 0, random.Length);
            GlobalConfig.RandomGeneratorCryptSecure(sesId, 0, sesId.Length);

            List<Extension> extensions = new List<Extension>
            {
                new ClientSupportedVersionsExtension(new ushort[] { 0x0304 }),
                new SignatureSchemeListExtension(config.SignatureSchemes, ExtensionType.SignatureAlgorithms),
                new SupportedGroupExtension(config.NamedGroups),
                new PreSharedKeyExchangeModeExtension(new PreSharedKeyExchangeModeExtension.PskKeyExchangeMode[] { PreSharedKeyExchangeModeExtension.PskKeyExchangeMode.PskDheKe })
            };

            if (config.ExtensionRecordSizeLimit.HasValue)
            {
                messageIO.SetRecordSizeLimit(config.ExtensionRecordSizeLimit.Value);
                extensions.Add(new RecordSizeLimitExtension(config.ExtensionRecordSizeLimit.Value));
            }

            if (config.ExtensionALPNConfig != null)
                extensions.Add(new ProtocolNameListExtension(config.ExtensionALPNConfig.ProtocolList.ToArray()));

            if (config.ExtensionClientConfigServerName != null)
            {
                var serverName = new ServerNameListClientHelloExtension.ServerName(ServerNameListClientHelloExtension.NameTypeEnum.HostName, config.ExtensionClientConfigServerName.HostName);
                extensions.Add(new ServerNameListClientHelloExtension(new ServerNameListClientHelloExtension.ServerName[] { serverName }));
            }

            foreach (var toSendInKeyShare in config.NamedGroupsToSendInKeyExchangeInClientHello1)
            {
                byte[] keyShareToSendRawBytes, privateKey;

                crypto.GeneratePrivateKeyAndKeyShareToSend(toSendInKeyShare, out keyShareToSendRawBytes, out privateKey);
                generatedPrivateKeys[toSendInKeyShare] = privateKey;

                generatedKeysToExchange.Add(new KeyShareEntry(SupportedGroupExtension.NamedGroup.X25519, keyShareToSendRawBytes));
            }

            extensions.Add(new KeyShareClientHelloExtension(generatedKeysToExchange.ToArray()));

            clientHello = new ClientHello(random, sesId, suites, extensions);
            AppendLastExtensionPreSharedKey(clientHello);

            messageIO.WriteHandshake(clientHello);
            context.ClientHello1 = clientHello;

            commandQueue.Enqueue(ClientProtocolCommand.Handshake_ServerHelloOrHelloRetryRequest);
        }

        private void Start_Connect()
        {
            state = ClientProtocolState.Handshake;
            commandQueue.Enqueue(ClientProtocolCommand.Handshake_ClientHello1);

            messageIO.SetBackwardCompatibilityMode(true, true);
        }
    }
}
