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
using Arctium.Shared.Helpers;
using Arctium.Standards.Connection.Tls.Tls13.API.Extensions;

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

        public struct ConnectedInfo
        {
            public byte[] ExtensionResultALPN;
            public ExtensionServerConfigServerName.ResultAction? ExtensionResultServerName;
            public byte[][] ClientHandshakeAuthenticationCertificatesSentByClient;
            public bool ClientSupportPostHandshakeAuthentication;
        }

        class PostHandshakeAuthContext
        {
            public CertificateRequest CertificateRequest;
            public ByteBuffer hsctx = new ByteBuffer();
            public Certificate Certificate;
            public X509Certificate ClientX509Certificate;

            public PostHandshakeAuthContext(CertificateRequest certificateRequest)
            {
                CertificateRequest = certificateRequest;
            }

            public void AddHandshakeContext(byte[] buffer, int offset, int length)
            {
                hsctx.Append(buffer, offset, length);
            }
        }

        class Context
        {
            public ClientHello ClientHello1;
            public ClientHello ClientHello2;
            public ServerHello HelloRetryRequest;

            public Model.CipherSuite SelectedCipherSuite;
            public bool IsPskSessionResumption;
            public PreSharedKeyExchangeModeExtension.PskKeyExchangeMode KeyExchangeMode;
            public int CH2Offset;
            public X509CertWithKey SelectedCertificate;
            public SignatureSchemeListExtension.SignatureScheme SelectedSignatureScheme
            {
                get { if (!selectedSignatureScheme.HasValue) { Validation.ThrowInternal(); } return selectedSignatureScheme.Value; }
                set { selectedSignatureScheme = value; }
            }

            public SignatureSchemeListExtension.SignatureScheme? selectedSignatureScheme;

            public PskTicket SelectedPskTicket { get; internal set; }
            public ushort? ExtensionRecordSizeLimit { get; internal set; }
            public X509Certificate ClientCertificateOnHandshake { get; internal set; }
            public CertificateRequest PostHandshakeCertificateRequest { get; internal set; }
            public bool KeyUpdateToSendUpdateRequested { get; internal set; }

            public ServerProtocolCommand? CommandAfterPostHandshakeProcessingFinished = null;

            public bool ClientSupportPostHandshakeAuthentication = false;

            public byte[] ExtensionResultALPN;
            public API.Extensions.ExtensionServerConfigServerName.ResultAction? ExtensionResultServerName;
            public byte[][] ClientHandshakeAuthenticationCertificatesSentByClient;

            // stores all certificate requests that was sent with handshakecontext
            // for each certificate separately
            public List<PostHandshakeAuthContext> PostHandshakeClientAuthSended = new List<PostHandshakeAuthContext>();
            public PostHandshakeAuthContext PostHandshakeClientAuth_CurrentProcessing = null;
        }

        private byte[] applicationDataBuffer = new byte[Tls13Const.RecordLayer_MaxPlaintextApplicationDataLength];
        private int applicationDataLength;

        private byte[] writeApplicationDataBuffer;
        private long writeApplicationDataOffset;
        private long writeApplicationDataLength;

        private Queue<ServerProtocolCommand> CommandQueue;

        private ServerProtocolCommand Command;

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
            CommandQueue = new Queue<ServerProtocolCommand>();
        }

        public void PostHandshakeKeyUpdate(bool updateRequested)
        {
            context.KeyUpdateToSendUpdateRequested = updateRequested;
            ProcessCommandFromOutside(ServerProtocolCommand.Connected_OutsideCommandStartPostHandshakeKeyUpdate);
        }

        private void MessageIO_OnHandshakeReadWrite(byte[] buffer, int offset, int length)
        {
            hsctx.Append(buffer, offset, length);
        }

        public ConnectedInfo Listen()
        {
            CommandQueue.Enqueue(ServerProtocolCommand.Start);
            State = ServerProtocolState.Listen;

            ProcessCommandLoop();

            var info = new ConnectedInfo();
            info.ExtensionResultALPN = context.ExtensionResultALPN;
            info.ExtensionResultServerName = context.ExtensionResultServerName;
            info.ClientHandshakeAuthenticationCertificatesSentByClient = context.ClientHandshakeAuthenticationCertificatesSentByClient;
            info.ClientSupportPostHandshakeAuthentication = context.ClientSupportPostHandshakeAuthentication;

            return info;
        }

        public void Close()
        {
        }

        public void TryWaitPostHandshake()
        {
            ProcessCommandFromOutside(ServerProtocolCommand.Connected_TryWaitPostHandshake);
        }

        public void PostHandshakeClientAuthentication()
        {
            ProcessCommandFromOutside(ServerProtocolCommand.Connected_StartPostHandshakeCertificateRequest);
        }

        /// <summary>
        /// Removes all data from <see cref="ApplicationDataBuffer"/> and loads next part of application data received.
        /// Result length of data is in <see cref="ApplicationDataLength"/>.
        /// </summary>
        public void LoadNextApplicationData()
        {
            CommandQueue.Enqueue(ServerProtocolCommand.Connected_LoadApplicationData);
            ProcessCommandLoop();
        }

        public void WriteApplicationData(byte[] buffer, long offset, long length)
        {
            writeApplicationDataBuffer = buffer;
            writeApplicationDataOffset = offset;
            writeApplicationDataLength = length;

            ProcessCommandFromOutside(ServerProtocolCommand.Connected_WriteApplicationData);
        }

        private void ProcessCommandFromOutside(ServerProtocolCommand command)
        {
            CommandQueue.Enqueue(command);
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
                case ServerProtocolCommand.PostHandshake_NewSessionTicket: PostHandshake_NewSessionTicket(); break;
                case ServerProtocolCommand.PostHandshake_CertificateRequest: PostHandshake_CertificateRequest(); break;
                case ServerProtocolCommand.PostHandshake_Certificate: PostHandshake_Certificate(); break;
                case ServerProtocolCommand.PostHandshake_CertificateVerify: PostHandshake_CertificateVerify(); break;
                case ServerProtocolCommand.PostHandshake_Finished: PostHandshake_Finished(); break;
                case ServerProtocolCommand.PostHandshake_FinishedProcessingOfPostHandshake: PostHandshake_FinishedProcessingOfPostHandshake(); break;
                case ServerProtocolCommand.PostHandshake_SendKeyUpdate: PostHandshake_SendKeyUpdate(); break;
                case ServerProtocolCommand.PostHandshake_ReceivedKeyUpdate: PostHandshake_ReceivedKeyUpdate(); break;
                default: throw new Tls13Exception("command not valid for this state");
            }
        }

        private void ListenState()
        {
            if (Command != ServerProtocolCommand.Start) throw new Tls13Exception("Command not valid for this state");

            State = ServerProtocolState.Handshake;
            CommandQueue.Enqueue(ServerProtocolCommand.Handshake_FirstClientHello);
        }

        private void ConnectedState()
        {
            switch (Command)
            {
                case ServerProtocolCommand.Connected_LoadApplicationData: LoadApplicationData(); break;
                case ServerProtocolCommand.Connected_WriteApplicationData: WriteApplicationData(); break;
                case ServerProtocolCommand.Connected_StartReceivedPostHandshake: Connected_StartReceivedPostHandshake(); break;
                case ServerProtocolCommand.Connected_StartPostHandshakeCertificateRequest: Connected_StartPostHandshakeCertificateRequest();  break;
                case ServerProtocolCommand.Connected_TryWaitPostHandshake: Connected_TryWaitPostHandshake(); break;
                case ServerProtocolCommand.Connected_OutsideCommandStartPostHandshakeKeyUpdate: Connected_OutsideCommandStartPostHandshakeKeyUpdate(); break;
                default: throw new NotImplementedException("Operation is invalid for current state. current state: connected");
            }
        }

        private void HandshakeState()
        {
            switch (Command)
            {
                case ServerProtocolCommand.Handshake_FirstClientHello: FirstClientHello(); break;
                case ServerProtocolCommand.Handshake_ClientHello1: ClientHello1(); break;
                case ServerProtocolCommand.Handshake_SendHelloRetryRequestIfNeeded: Handshake_SendHelloRetryRequestIfNeeded(); break;
                case ServerProtocolCommand.Handshake_ServerHelloNotPsk: ServerHelloNotPsk();  break;
                case ServerProtocolCommand.Handshake_ServerHelloPsk_Dhe: Handshake_ServerHelloPsk_Dhe(); break;
                case ServerProtocolCommand.Handshake_EncryptedExtensions: EncryptedExtensions(); break;
                case ServerProtocolCommand.Handshake_ServerCertificate: ServerCertificate();  break;
                case ServerProtocolCommand.Handshake_ServerCertificateVerify: ServerCertificateVerify();  break;
                case ServerProtocolCommand.Handshake_ServerFinished: ServerFinished(); break;
                case ServerProtocolCommand.Handshake_ClientFinished: ClientFinished(); break;
                case ServerProtocolCommand.Handshake_HandshakeCompletedSuccessfully: Handshake_HandshakeCompletedSuccessfully(); break;
                case ServerProtocolCommand.Handshake_CertificateRequest: Handshake_CertificateRequest(); break;
                case ServerProtocolCommand.Handshake_ClientCertificate: Handshake_ClientCertificate(); break;
                case ServerProtocolCommand.Handshake_ClientCertificateVerify: Handshake_ClientCertificateVerity(); break;
                default: throw new Tls13Exception("command not valid for this state");
            }
        }

        private void PostHandshake_ReceivedKeyUpdate()
        {
            var keyUpdate = messageIO.ReadHandshakeMessage<KeyUpdate>();

            messageIO.KeyUpdateForReading(crypto);

            if (keyUpdate.RequestUpdate == KeyUpdate.KeyUpdateRequest.UpdateRequested)
            {
                CommandQueue.Enqueue(ServerProtocolCommand.PostHandshake_SendKeyUpdate);
            }
            else
            {
                CommandQueue.Enqueue(ServerProtocolCommand.PostHandshake_FinishedProcessingOfPostHandshake);
            }
        }

        private void PostHandshake_SendKeyUpdate()
        {
            var keyUpdate = new KeyUpdate(context.KeyUpdateToSendUpdateRequested ? KeyUpdate.KeyUpdateRequest.UpdateRequested : KeyUpdate.KeyUpdateRequest.NotRequested);

            messageIO.WriteHandshake(keyUpdate);
            messageIO.KeyUpdateForWriting(crypto);

            CommandQueue.Enqueue(ServerProtocolCommand.PostHandshake_FinishedProcessingOfPostHandshake);
        }

        private void Connected_OutsideCommandStartPostHandshakeKeyUpdate()
        {
            State = ServerProtocolState.PostHandshake;
            context.CommandAfterPostHandshakeProcessingFinished = null;

            CommandQueue.Enqueue(ServerProtocolCommand.PostHandshake_SendKeyUpdate);
        }


        private void Connected_StartPostHandshakeCertificateRequest()
        {
            if (config.PostHandshakeClientAuthentication == null) Validation.InvalidOperation("Not configured");
            if (!context.ClientSupportPostHandshakeAuthentication) Validation.InvalidOperation("Client do not support post handshake auth");

            context.CommandAfterPostHandshakeProcessingFinished = null;
            State = ServerProtocolState.PostHandshake;

            CommandQueue.Enqueue(ServerProtocolCommand.PostHandshake_CertificateRequest);
        }

        private void PostHandshake_FinishedProcessingOfPostHandshake()
        {
            State = ServerProtocolState.Connected;
            
            if (context.CommandAfterPostHandshakeProcessingFinished.HasValue)
            {
                CommandQueue.Enqueue(context.CommandAfterPostHandshakeProcessingFinished.Value);
                context.CommandAfterPostHandshakeProcessingFinished = null;
            }
        }

        private void PostHandshake_CertificateRequest()
        {
            var requestCtx = Guid.NewGuid().ToByteArray();
            List<Extension> extensions = new List<Extension>()
            {
                new SignatureSchemeListExtension(config.SignatureSchemes, ExtensionType.SignatureAlgorithms)
            };

            var oids = serverContext.OidFiltersExtension();
            var certAuthorities = serverContext.GetExtension_CertificateAuthorities();

            if (certAuthorities != null) extensions.Add(certAuthorities);

            if (oids != null)
            {
                extensions.Add(oids);
            }

            var certRequest = new CertificateRequest(requestCtx, extensions.ToArray());
            context.PostHandshakeCertificateRequest = certRequest;

            var authContext = new PostHandshakeAuthContext(certRequest);

            context.PostHandshakeClientAuthSended.Add(authContext);

            // must be with original hs context (starting from first client hello)
            // ClientHello1 ... ClientFinished + CertificateRequest
            // but 'CertificateRequest' is only one in new hsctx below, this is incorrect context:
            // [ClientHello1 ... ClientFinished] + [certrequest + clientcertificate + verify + finished] + [certrequest + cert + ver + finished] + ... + 
            // so need to store original hsctx and always append messages that are 
            // sent in this particular post-hs-auth
            authContext.hsctx.Append(hsctx.Buffer, 0, hsctx.DataLength);

            messageIO.OnHandshakeReadWrite += authContext.AddHandshakeContext;
            messageIO.WriteHandshake(certRequest);
            messageIO.OnHandshakeReadWrite -= authContext.AddHandshakeContext;

            CommandQueue.Enqueue(ServerProtocolCommand.PostHandshake_FinishedProcessingOfPostHandshake);
        }

        private void PostHandshake_Finished()
        {
            // compute before because readhandshakemesasge will update hsctx
            var current = context.PostHandshakeClientAuth_CurrentProcessing;
            var expectedFinished = crypto.ComputeFinishedVerData(current.hsctx, Endpoint.Client, true);
            var finished = messageIO.ReadHandshakeMessage<Finished>();

            bool finishedOk = MemOps.Memcmp(finished.VerifyData, expectedFinished);

            validate.Finished.AlertFatal(!finishedOk, AlertDescription.DecodeError, "post handshake client auth: finished verify data invalid");

            serverContext.Event_PostHandshakeClientAuthenticationSuccess(context.PostHandshakeClientAuth_CurrentProcessing.Certificate);

            messageIO.OnHandshakeReadWrite -= context.PostHandshakeClientAuth_CurrentProcessing.AddHandshakeContext;
            context.PostHandshakeClientAuthSended.Remove(context.PostHandshakeClientAuth_CurrentProcessing);
            context.PostHandshakeClientAuth_CurrentProcessing = null;
            
            CommandQueue.Enqueue(ServerProtocolCommand.PostHandshake_FinishedProcessingOfPostHandshake);
        }

        private void PostHandshake_CertificateVerify()
        {
            var certVerify = messageIO.BufferHandshakeDeserialize<CertificateVerify>();
            var current = context.PostHandshakeClientAuth_CurrentProcessing;

            var certOk = crypto.IsClientCertificateVerifyValid(current.hsctx.Buffer,
                current.hsctx.DataLength,
                certVerify,
                context.PostHandshakeClientAuth_CurrentProcessing.ClientX509Certificate);

            messageIO.ReadHandshakeMessage<CertificateVerify>();

            validate.CertificateVerify.AlertFatal(!certOk, AlertDescription.DecryptError, "Post handshake client auth: invalid certificate verify");

            CommandQueue.Enqueue(ServerProtocolCommand.PostHandshake_Finished);
        }

        private void PostHandshake_Certificate()
        {
            validate.Other.AlertFatal(
                context.PostHandshakeClientAuthSended.Count == 0,
                AlertDescription.UnexpectedMessage,
                "client sent post handshake certificate but certificate was not expected (server did not request certificate or " + 
                "(if multiple requests) requested less times than received certificates)");

            ByteBuffer b = new ByteBuffer();

            var cert = messageIO.BufferHandshakeDeserialize<Certificate>();

            var authContext = context.PostHandshakeClientAuthSended.FirstOrDefault(c => MemOps.Memcmp(c.CertificateRequest.CertificateRequestContext, cert.CertificateRequestContext));
            authContext.Certificate = cert;
            context.PostHandshakeClientAuth_CurrentProcessing = authContext;

            if (authContext == null)
                validate.Certificate.AlertFatal(AlertDescription.Illegal_parameter, "certificate request context does not match with any that was send (client sent unknow certificaterequestcontext)");

            // start tracking context (later this tracking must be removed)
            messageIO.OnHandshakeReadWrite += authContext.AddHandshakeContext;
            messageIO.ReadHandshakeMessage<Certificate>();

            var action = serverContext.PostHandshakeClientCertificate(cert);

            if (action != API.Messages.ServerConfigHandshakeClientAuthentication.Action.Success)
                validate.Certificate.AlertFatal((AlertDescription)action, "Post handshake client auth aborting by current configuration, error: " + action.ToString());

            if (cert.CertificateList.Length > 0)
            {
                try
                {
                    X509CertificateDeserializer deserializer = new X509CertificateDeserializer();
                    var x509Cert = deserializer.FromBytes(cert.CertificateList[0].CertificateEntryRawBytes);
                    authContext.ClientX509Certificate = x509Cert;
                }
                catch (Exception e)
                {
                    validate.Certificate.AlertFatal(AlertDescription.BadCertificate, "cannot deserialize certificate, bad certificate or not supported");
                }

                CommandQueue.Enqueue(ServerProtocolCommand.PostHandshake_CertificateVerify);
            }
            else
            {
                CommandQueue.Enqueue(ServerProtocolCommand.PostHandshake_Finished);
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
                for (int i = 0; i < 1; i++) CommandQueue.Enqueue(ServerProtocolCommand.PostHandshake_NewSessionTicket);
                State = ServerProtocolState.PostHandshake;
            }
            else
            {
                //CommandQueue.Enqueue(ServerProcolCommand.BreakLoopWaitForOtherCommand);
                State = ServerProtocolState.Connected;
            }

            messageIO.OnHandshakeReadWrite -= MessageIO_OnHandshakeReadWrite;
        }

        private void Connected_TryWaitPostHandshake()
        {
            var recordType = messageIO.BufferAnyRecordType();

            if (recordType == ContentType.Handshake) CommandQueue.Enqueue(ServerProtocolCommand.Connected_StartReceivedPostHandshake);
        }

        private void Connected_StartReceivedPostHandshake()
        {
            var type = messageIO.BufferHandshakeMessage();
            State = ServerProtocolState.PostHandshake;

            switch (type)
            {
                case HandshakeType.Certificate:
                    CommandQueue.Enqueue(ServerProtocolCommand.PostHandshake_Certificate); break;
                case HandshakeType.KeyUpdate:
                    CommandQueue.Enqueue(ServerProtocolCommand.PostHandshake_ReceivedKeyUpdate); break;
                default: validate.Other.AlertFatal(AlertDescription.UnexpectedMessage, "Not expected message received: " + type.ToString()); break;
            }
        }

        private void WriteApplicationData()
        {
            messageIO.WriteApplicationData(writeApplicationDataBuffer, writeApplicationDataOffset, writeApplicationDataLength);
        }

        private void LoadApplicationData()
        {
            if (!messageIO.TryLoadApplicationData(applicationDataBuffer, 0, out applicationDataLength))
            {
                context.CommandAfterPostHandshakeProcessingFinished = ServerProtocolCommand.Connected_LoadApplicationData;
                CommandQueue.Enqueue(ServerProtocolCommand.Connected_StartReceivedPostHandshake);
            }
        }

        private void ClientFinished()
        {
            // compute expected finished data before reading <finished> from client (because is not inclueded in calculations)
            var expectedClientFinished = crypto.ComputeFinishedVerData(hsctx, Endpoint.Client);
            var finished = messageIO.ReadHandshakeMessage<Finished>();
            bool clientFinishedOk = MemOps.Memcmp(finished.VerifyData, expectedClientFinished);

            validate.Finished.FinishedSigValid(clientFinishedOk);

            messageIO.ChangeRecordLayerCrypto(crypto, Crypto.RecordLayerKeyType.ApplicationData);
            
            messageIO.SetBackwardCompatibilityMode(
                compatibilityAllowRecordLayerVersionLower0x0303: false,
                compatibilitySilentlyDropUnencryptedChangeCipherSpec: false);

            State = ServerProtocolState.Handshake;
            crypto.SetupResumptionMasterSecret(hsctx);

            CommandQueue.Enqueue(ServerProtocolCommand.Handshake_HandshakeCompletedSuccessfully);
        }

        private void ServerFinished()
        {
            var finishedVerifyData = crypto.ComputeFinishedVerData(hsctx, Endpoint.Server);
            var finished = new Finished(finishedVerifyData);

            messageIO.WriteHandshake(finished);
            crypto.SetupMasterSecret(hsctx);
        }

        private void ServerCertificateVerify()
        {
            var signature = crypto.GenerateCertificateVerifySignature(hsctx, context.SelectedCertificate, context.SelectedSignatureScheme, Endpoint.Server);

            var certificateVerify = new CertificateVerify(context.SelectedSignatureScheme, signature);

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
            int dataToSignLen = hsctx.DataLength;
            var certVer = messageIO.ReadHandshakeMessage<CertificateVerify>();

            bool signatureOk = crypto.IsClientCertificateVerifyValid(hsctx.Buffer, dataToSignLen, certVer, context.ClientCertificateOnHandshake);

            validate.CertificateVerify.AlertFatal(!signatureOk, AlertDescription.DecryptError, "Invalid client certificate 'CertificateVerify' signature");
        }

        private void Handshake_ClientCertificate()
        {
            //messageIO.recordLayer.Read();
            var certificate = messageIO.ReadHandshakeMessage<Certificate>();

            var action = serverContext.ClientCertificate(certificate);

            if (certificate.CertificateList.Length > 0)
            {
                try
                {
                    X509CertificateDeserializer deserializer = new X509CertificateDeserializer();
                    context.ClientCertificateOnHandshake = deserializer.FromBytes(certificate.CertificateList[0].CertificateEntryRawBytes);
                }
                catch (Exception e)
                {
                    validate.Certificate.AlertFatal(AlertDescription.BadCertificate,
                        "Cannot deserialize X509 certificate received from client in handshake (after server requested)");
                }
            }

            if (action != API.Messages.ServerConfigHandshakeClientAuthentication.Action.Success)
            {
                validate.Certificate.AlertFatal((AlertDescription)action, "Current configuration aborting client authentication (return action was not Success)");
            }

            context.ClientHandshakeAuthenticationCertificatesSentByClient = certificate.CertificateList.Select(c => c.CertificateEntryRawBytes).ToArray();

            if (certificate.CertificateList.Length > 0)
            {
                CommandQueue.Enqueue(ServerProtocolCommand.Handshake_ClientCertificateVerify);
            }

            CommandQueue.Enqueue(ServerProtocolCommand.Handshake_ClientFinished);
        }

        private void Handshake_CertificateRequest()
        {
            // extension with signature algorithms must be specified 
            var ext = new List<Extension>
            {
                new SignatureSchemeListExtension(config.SignatureSchemes, ExtensionType.SignatureAlgorithms)
            };

            var oidFiltersExtension = serverContext.OidFiltersExtension();
            var extensionCertAuthorities = serverContext.GetExtension_CertificateAuthorities();

            if (oidFiltersExtension != null) ext.Add(oidFiltersExtension);
            if (extensionCertAuthorities != null) ext.Add(extensionCertAuthorities);

            var certRequest = new CertificateRequest(new byte[0], ext.ToArray());

            messageIO.WriteHandshake(certRequest);
        }

        private void EncryptedExtensions()
        {
            var clientHello = context.ClientHello2 ?? context.ClientHello1;

            List<Extension> extensions = new List<Extension>
            {
            };

            // Extension: Server Name
            if (clientHello.TryGetExtension<ServerNameListClientHelloExtension>(ExtensionType.ServerName, out var serverNameExt))
            {
                context.ExtensionResultServerName = serverContext.HandleExtensionServerName(serverNameExt);
                bool abort = context.ExtensionResultServerName == API.Extensions.ExtensionServerConfigServerName.ResultAction.AbortFatalAlertUnrecognizedName;
                
                validate.Handshake.AlertFatal(abort, AlertDescription.UnrecognizedName,
                    "server name extension from client caused handshake failure. " +
                    "This is because current configuration of ServerName returned action to abort handshake");

                if (context.ExtensionResultServerName == ExtensionServerConfigServerName.ResultAction.Success) extensions.Add(new ServerNameListServerHelloExtension());
            }

            // Extension: ALPN

            if (clientHello.TryGetExtension<ProtocolNameListExtension>(ExtensionType.ApplicationLayerProtocolNegotiation, out var alpnExtension))
            {
                var result = serverContext.ExtensionHandleALPN(alpnExtension);

                switch (result.ActionType)
                {
                    case API.Extensions.ExtensionServerALPN.ResultType.Success:
                        var selectedalpn = alpnExtension.ProtocolNamesList[result.SelectedIndex];
                        extensions.Add(new ProtocolNameListExtension(new byte[][] { selectedalpn }));
                        context.ExtensionResultALPN = selectedalpn;
                        break;
                    case API.Extensions.ExtensionServerALPN.ResultType.NotSelectedFatalAlert:
                        validate.Extensions.ALPN_AlertFatal_NoApplicationProtocol();
                        break;
                    case API.Extensions.ExtensionServerALPN.ResultType.NotSelectedIgnore:
                        /* ignore, simulate that server dont know this extension */
                        break;
                    default:
                        Validation.ThrowInternal("impossible, invalid implementation not all in switch handled");
                        break;
                }
            }

            // Extension: Record Size Limit
            
            if (clientHello.TryGetExtension<RecordSizeLimitExtension>(ExtensionType.RecordSizeLimit, out var recordSizeLimitExt))
            {
                ushort maxRecordSizeLimit = recordSizeLimitExt.RecordSizeLimit;

                if (config.ExtensionRecordSizeLimit.HasValue)
                {
                    maxRecordSizeLimit = (maxRecordSizeLimit > config.ExtensionRecordSizeLimit.Value) ?
                        config.ExtensionRecordSizeLimit.Value : maxRecordSizeLimit;
                }

                context.ExtensionRecordSizeLimit = maxRecordSizeLimit;
                messageIO.SetRecordSizeLimit(maxRecordSizeLimit);
                extensions.Add(new RecordSizeLimitExtension(context.ExtensionRecordSizeLimit.Value));
                messageIO.SetRecordSizeLimit(context.ExtensionRecordSizeLimit.Value);
            }

            var encryptedExtensions = new EncryptedExtensions(extensions.ToArray());
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
                CommandQueue.Enqueue(ServerProtocolCommand.Handshake_ServerHelloNotPsk);
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

            CommandQueue.Enqueue(ServerProtocolCommand.Handshake_EncryptedExtensions);
            CommandQueue.Enqueue(ServerProtocolCommand.Handshake_ServerFinished);
            CommandQueue.Enqueue(ServerProtocolCommand.Handshake_ClientFinished);
        }

        private void ServerHelloNotPsk()
        {
            // full crypto (not PSK), select: ciphersuite, (ec)dhe group, signature algorithm
            SignatureSchemeListExtension clientSupporetdCertSignatures = null;
            var clientSupportedSignatures = context.ClientHello1.GetExtension<SignatureSchemeListExtension>(ExtensionType.SignatureAlgorithms).Schemes;
            context.ClientHello1.TryGetExtension<SignatureSchemeListExtension>(ExtensionType.SignatureAlgorithmsCert, out clientSupporetdCertSignatures);

            SignatureSchemeListExtension.SignatureScheme? selectedSigScheme = null;

            bool selectedOk = crypto.SelectSigAlgoAndCert(
                clientSupportedSignatures,
                clientSupporetdCertSignatures?.Schemes,
                config.CertificatesWithKeys,
                ref selectedSigScheme,
                ref context.SelectedCertificate);

            validate.Handshake.AlertFatal(!selectedOk, AlertDescription.HandshakeFailure, "configured x509 certificates and signatue schemes does not match mutually with supported with client");

            context.SelectedSignatureScheme = selectedSigScheme.Value;

            var clientHello = context.ClientHello2 ?? context.ClientHello1;
            KeyShareEntry keyShareEntry = null;
            ServerHello serverHello;
            var random = GlobalConfig.RandomByteArray(Tls13Const.HelloRandomFieldLength);
            var legacySessId = context.ClientHello1.LegacySessionId;

            List<Extension> extensions = new List<Extension>()
            {
                ServerSupportedVersionsExtension.ServerHelloTls13, //todo uncomment
            };

            keyShareEntry = clientHello.GetExtension<KeyShareClientHelloExtension>(ExtensionType.KeyShare)
                .ClientShares
                .FirstOrDefault(share => share.NamedGroup == crypto.SelectedNamedGroup);

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

            CommandQueue.Enqueue(ServerProtocolCommand.Handshake_EncryptedExtensions);

            if (config.HandshakeClientAuthentication != null)
            {
                CommandQueue.Enqueue(ServerProtocolCommand.Handshake_CertificateRequest);
            }
            
            CommandQueue.Enqueue(ServerProtocolCommand.Handshake_ServerCertificate);
            CommandQueue.Enqueue(ServerProtocolCommand.Handshake_ServerCertificateVerify);
            CommandQueue.Enqueue(ServerProtocolCommand.Handshake_ServerFinished);

            if (config.HandshakeClientAuthentication != null)
            {
                CommandQueue.Enqueue(ServerProtocolCommand.Handshake_ClientCertificate);
            }
            else
            {
                CommandQueue.Enqueue(ServerProtocolCommand.Handshake_ClientFinished);
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
                validate.ClientHello.GeneralValidateClientHello2(context.ClientHello2, context.ClientHello1, context.HelloRetryRequest);

                var selectedByServer = ((KeyShareHelloRetryRequestExtension)context.HelloRetryRequest.Extensions.First(ext => ext.ExtensionType == ExtensionType.KeyShare)).SelectedGroup;
                var sharedFromClient = context.ClientHello2.GetExtension<KeyShareClientHelloExtension>(ExtensionType.KeyShare).ClientShares;

                validate.Handshake.AlertFatal(sharedFromClient.Count() != 1 || sharedFromClient[0].NamedGroup != selectedByServer,
                    AlertDescription.Illegal_parameter,
                    "Invalid share in ClientHello2 (after HelloRetry). Not single share or other that select on server");

                hasPskExtension = context.ClientHello2.TryGetExtension<PreSharedKeyClientHelloExtension>(ExtensionType.PreSharedKey, out _);
            }

            if (hasPskExtension)
            {
                CommandQueue.Enqueue(ServerProtocolCommand.Handshake_ServerHelloPsk_Dhe);
            }
            else
            {
                CommandQueue.Enqueue(ServerProtocolCommand.Handshake_ServerHelloNotPsk);
            }
        }

        private void FirstClientHello()
        {
            messageIO.SetBackwardCompatibilityMode(
                compatibilityAllowRecordLayerVersionLower0x0303: true,
                compatibilitySilentlyDropUnencryptedChangeCipherSpec: false);

            CommandQueue.Enqueue(ServerProtocolCommand.Handshake_ClientHello1);
        }

        private void ClientHello1()
        {
            ClientHello clientHello = messageIO.ReadHandshakeMessage<ClientHello>();
            validate.ClientHello.GeneralValidateClientHello(clientHello);

            context.ClientHello1 = clientHello;
            PreSharedKeyClientHelloExtension _;
            
            bool pskKeTicketExists = false, cipherSuiteOk, groupOk;
            bool hasPskExtension = clientHello.TryGetExtension<PreSharedKeyClientHelloExtension>(ExtensionType.PreSharedKey, out _);
            context.ClientSupportPostHandshakeAuthentication = clientHello.Extensions.Any(e => e.ExtensionType == ExtensionType.PostHandshakeAuth);

            if (hasPskExtension)
            {
                var modes = clientHello.GetExtension<PreSharedKeyExchangeModeExtension>(ExtensionType.PskKeyExchangeModes).KeModes;
                
                if (pskKeTicketExists && modes.Contains(PreSharedKeyExchangeModeExtension.PskKeyExchangeMode.PskKe))
                {
                    CommandQueue.Enqueue(ServerProtocolCommand.Handshake_ServerHelloPsk_Ke);
                    return;
                }
            }

            crypto.SelectCipherSuite(clientHello, out cipherSuiteOk);
            crypto.SelectEcEcdheGroup(clientHello, out groupOk);

            validate.Handshake.AlertFatal(!(cipherSuiteOk && groupOk), AlertDescription.HandshakeFailure, "client and server ececdhe or cipher suites does not match mutually");

            CommandQueue.Enqueue(ServerProtocolCommand.Handshake_SendHelloRetryRequestIfNeeded);

            messageIO.SetBackwardCompatibilityMode(
                compatibilityAllowRecordLayerVersionLower0x0303: false,
                compatibilitySilentlyDropUnencryptedChangeCipherSpec: true);
        }
    }
}
