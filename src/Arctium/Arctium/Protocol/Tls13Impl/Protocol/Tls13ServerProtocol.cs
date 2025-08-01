/*
 *  TLS 1.3 Server Implementation
 *  Implemented by NeuroXiq 2022
 */


// todo if time this (and client) should
// be rewritted into better implementation
// state machine like in rfc 8446 says

// using Arctium.Protocol.Tls13.
using Arctium.Shared;
using Arctium.Shared;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Standards.X509.X509Cert;
using Arctium.Shared.Helpers;
using Arctium.Protocol.Tls13;
using Arctium.Protocol.Tls13.Extensions;
using Arctium.Protocol.Tls13.Messages;
using Arctium.Protocol.Tls13Impl.Model;
using Arctium.Protocol.Tls13Impl.Protocol.Helpers;
using Arctium.Protocol.Tls13Impl.Model.Extensions;

namespace Arctium.Protocol.Tls13Impl.Protocol
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
            public bool IsPskSessionResumption;
            public Model.CipherSuite CipherSuite;

            public ReadOnlyMemory<byte> InstanceId;
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
            public ExtensionServerConfigServerName.ResultAction? ExtensionResultServerName;
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

        public ServerProtocolState State { get; private set; }
        private MessageIO messageIO;
        private Crypto crypto;
        private Validate validate;
        private ByteBuffer hsctx;
        private Context context;
        private Tls13ServerConfig config { get { return serverContext.Config; } }
        private Tls13ServerProtocolInstanceContext serverContext;
        private bool isQuicIntegration;
        private QUICv1Impl.QuicIntegrationTlsNetworkStream quicIntegration;

        public Tls13ServerProtocol(Stream networkStream, Tls13ServerProtocolInstanceContext serverContext)
        {
            this.serverContext = serverContext;
            isQuicIntegration = networkStream is QUICv1Impl.QuicIntegrationTlsNetworkStream;
            quicIntegration = networkStream as QUICv1Impl.QuicIntegrationTlsNetworkStream;

            validate = new Validate(new Validate.ValidationErrorHandler(SendAlertFatal));
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
            info.IsPskSessionResumption = context.IsPskSessionResumption;
            info.InstanceId = serverContext.InstanceId;
            info.CipherSuite = crypto.SelectedCipherSuite;

            return info;
        }

        public void Close()
        {
            ProcessCommandFromOutside(ServerProtocolCommand.Connected_OutsideCommandClose);
        }

        public void WaitForAnyProtocolData()
        {
            ProcessCommandFromOutside(ServerProtocolCommand.Connected_OutsideCommandWaitForAnyProtocolData);
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
            try
            {
                InnerProcessCommandLoop();
            }
            catch (Tls13ReceivedAlertException e)
            {
                if (e.AlertDescription == AlertDescription.CloseNotify)
                {
                    State = ServerProtocolState.Closed;
                }
                else
                {
                    throw e;
                }
            }
            catch
            {
                throw;
            }
        }

        private void SendAlertFatal(Tls13AlertException alertExc)
        {
            try
            {
                messageIO.WriteAlert(AlertLevel.Fatal, alertExc.AlertDescription);
            }
            catch (Exception e)
            {
            }
        }

        private void InnerProcessCommandLoop()
        {
            while (CommandQueue.Count > 0)
            {
                Command = CommandQueue.Dequeue();

                switch (State)
                {
                    case ServerProtocolState.Listen: ListenState(); break;
                    case ServerProtocolState.Handshake: HandshakeState(); break;
                    case ServerProtocolState.Connected: ConnectedState(); break;
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
                case ServerProtocolCommand.Connected_StartPostHandshakeCertificateRequest: Connected_StartPostHandshakeCertificateRequest(); break;
                case ServerProtocolCommand.Connected_OutsideCommandWaitForAnyProtocolData: Connected_OutsideCommandWaitForAnyProtocolData(); break;
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
                case ServerProtocolCommand.Handshake_ServerHelloNotPsk: ServerHelloNotPsk(); break;
                case ServerProtocolCommand.Handshake_ServerHelloPsk_Dhe: Handshake_ServerHelloPsk_Dhe(); break;
                case ServerProtocolCommand.Handshake_EncryptedExtensions: EncryptedExtensions(); break;
                case ServerProtocolCommand.Handshake_ServerCertificate: ServerCertificate(); break;
                case ServerProtocolCommand.Handshake_ServerCertificateVerify: ServerCertificateVerify(); break;
                case ServerProtocolCommand.Handshake_ServerFinished: ServerFinished(); break;
                case ServerProtocolCommand.Handshake_ClientFinished: ClientFinished(); break;
                case ServerProtocolCommand.Handshake_HandshakeCompletedSuccessfully: Handshake_HandshakeCompletedSuccessfully(); break;
                case ServerProtocolCommand.Handshake_CertificateRequest: Handshake_CertificateRequest(); break;
                case ServerProtocolCommand.Handshake_ClientCertificate: Handshake_ClientCertificate(); break;
                case ServerProtocolCommand.Handshake_ClientCertificateVerify: Handshake_ClientCertificateVerity(); break;
                case ServerProtocolCommand.Connected_OutsideCommandClose: Connected_OutsideCommandClose(); break;
                default: throw new Tls13Exception("command not valid for this state");
            }
        }

        private void Connected_OutsideCommandClose()
        {
            if (State == ServerProtocolState.Closed) return;

            messageIO.WriteAlert(AlertLevel.Warning, AlertDescription.CloseNotify);
            State = ServerProtocolState.Closed;
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
            validate.CertificateVerify.GeneralValidate(context.PostHandshakeClientAuth_CurrentProcessing.CertificateRequest, certVerify);

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

            if (action != ServerConfigHandshakeClientAuthentication.Action.Success)
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
            uint ageAdd = (uint)Environment.TickCount;
            byte[] nonce = Guid.NewGuid().ToByteArray();
            byte[] ticket = Guid.NewGuid().ToByteArray();

            NewSessionTicket newSessTicket = new NewSessionTicket(lifetime, ageAdd, nonce, ticket, new Extension[0]);

            serverContext.SavePskTicket(crypto.ResumptionMasterSecret,
                newSessTicket.Ticket,
                newSessTicket.TicketNonce,
                newSessTicket.TicketLifetime,
                newSessTicket.TicketAgeAdd,
                crypto.SelectedCipherSuiteHashFunctionId);

            GREASE(newSessTicket);

            messageIO.WriteHandshake(newSessTicket);
        }

        private void Handshake_HandshakeCompletedSuccessfully()
        {
            if (config.PreSharedKey != null)
            {
                int ticketsCount = config.PreSharedKey.NewSessionTicketsCount;

                if (ticketsCount > 0)
                {
                    for (int i = 0; i < ticketsCount; i++)
                        CommandQueue.Enqueue(ServerProtocolCommand.PostHandshake_NewSessionTicket);

                    State = ServerProtocolState.PostHandshake;
                }

                context.CommandAfterPostHandshakeProcessingFinished = null;
                CommandQueue.Enqueue(ServerProtocolCommand.PostHandshake_FinishedProcessingOfPostHandshake);
            }
            else
            {
                //CommandQueue.Enqueue(ServerProcolCommand.BreakLoopWaitForOtherCommand);
                State = ServerProtocolState.Connected;
            }
        }

        private void Connected_OutsideCommandWaitForAnyProtocolData()
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

            //Console.WriteLine("hsctx s1:");
            //MemDump.HexDump(hsctx.Buffer, 0, hsctx.DataLength, 1, 64);
            //Console.WriteLine("-----");

            var finished = messageIO.ReadHandshakeMessage<Finished>();
            bool clientFinishedOk = MemOps.Memcmp(finished.VerifyData, expectedClientFinished);

            validate.Finished.FinishedSigValid(clientFinishedOk);

            messageIO.ChangeRecordLayerReadCrypto(crypto, crypto.ClientApplicationTrafficSecret0);

            messageIO.SetBackwardCompatibilityMode(
                compatibilityAllowRecordLayerVersionLower0x0303: false,
                compatibilitySilentlyDropUnencryptedChangeCipherSpec: false);

            State = ServerProtocolState.Handshake;
            crypto.SetupResumptionMasterSecret(hsctx);

            CommandQueue.Enqueue(ServerProtocolCommand.Handshake_HandshakeCompletedSuccessfully);
            messageIO.OnHandshakeReadWrite -= MessageIO_OnHandshakeReadWrite;
        }

        private void ServerFinished()
        {
            var finishedVerifyData = crypto.ComputeFinishedVerData(hsctx, Endpoint.Server);
            var finished = new Finished(finishedVerifyData);

            messageIO.WriteHandshake(finished);
            crypto.SetupMasterSecret(hsctx);
            messageIO.ChangeRecordLayerWriteCrypto(crypto, crypto.ServerApplicationTrafficSecret0);
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

            if (action != ServerConfigHandshakeClientAuthentication.Action.Success)
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
            GREASE(certRequest);

            messageIO.WriteHandshake(certRequest);
        }

        private void EncryptedExtensions()
        {
            var clientHello = context.ClientHello2 ?? context.ClientHello1;

            List<Extension> extensions = new List<Extension>
            {
            };

            // Extension: Quic
            if (isQuicIntegration)
            {
                extensions.Add(quicIntegration.GetQuicTransportParametersServer(clientHello.GetExtension<QuicTransportParametersExtension>(ExtensionType.QuicTransportParameters)));
            }

            // Extension: Server Name
            if (clientHello.TryGetExtension<ServerNameListClientHelloExtension>(ExtensionType.ServerName, out var serverNameExt))
            {
                context.ExtensionResultServerName = serverContext.HandleExtensionServerName(serverNameExt);
                bool abort = context.ExtensionResultServerName == ExtensionServerConfigServerName.ResultAction.AbortFatalAlertUnrecognizedName;

                validate.Handshake.AlertFatal(abort, AlertDescription.UnrecognizedName,
                    "server name extension from client caused handshake failure. " +
                    "This is because current configuration of ServerName returned action to abort handshake");

                if (context.ExtensionResultServerName == ExtensionServerConfigServerName.ResultAction.Success) extensions.Add(new ServerNameListServerHelloExtension());
            }

            // Extension: ALPN

            if (clientHello.TryGetExtension<ProtocolNameListExtension>(ExtensionType.ApplicationLayerProtocolNegotiation, out var alpnExtension))
            {
                serverContext.ExtensionHandleALPN(alpnExtension, out var ignore, out var alertFatal, out int? selectedIndex);

                if (alertFatal.HasValue)
                {
                    validate.Extensions.ALPN_AlertFatal_NoApplicationProtocol();
                }
                else if (ignore)
                {
                    // ignore
                }
                else
                {
                    var selectedalpn = alpnExtension.ProtocolNamesList[selectedIndex.Value];
                    extensions.Add(new ProtocolNameListExtension(new byte[][] { selectedalpn }));
                    context.ExtensionResultALPN = selectedalpn;
                }
            }

            // Extension: Record Size Limit

            if (clientHello.TryGetExtension<RecordSizeLimitExtension>(ExtensionType.RecordSizeLimit, out var recordSizeLimitExt))
            {
                ushort maxRecordSizeLimit = recordSizeLimitExt.RecordSizeLimit;

                if (config.ExtensionRecordSizeLimit.HasValue)
                {
                    maxRecordSizeLimit = maxRecordSizeLimit > config.ExtensionRecordSizeLimit.Value ?
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
            // messageIO.ChangeRecordLayerCrypto(crypto, Crypto.RecordLayerKeyType.Handshake);
            
            messageIO.ChangeRecordLayerReadCrypto(crypto, crypto.ClientHandshakeTrafficSecret);
            messageIO.ChangeRecordLayerWriteCrypto(crypto, crypto.ServerHandshakeTrafficSecret);

            CommandQueue.Enqueue(ServerProtocolCommand.Handshake_EncryptedExtensions);
            CommandQueue.Enqueue(ServerProtocolCommand.Handshake_ServerFinished);
            CommandQueue.Enqueue(ServerProtocolCommand.Handshake_ClientFinished);
        }

        private void ServerHelloNotPsk()
        {
            // full crypto (not PSK), select: ciphersuite, (ec)dhe group, signature algorithm
            SignatureSchemeListExtension clientSupporetdCertSignatures = null;
            var clientSupportedSignatures = context.ClientHello1.GetExtension<SignatureSchemeListExtension>(ExtensionType.SignatureAlgorithms).Schemes;
            context.ClientHello1.TryGetExtension(ExtensionType.SignatureAlgorithmsCert, out clientSupporetdCertSignatures);

            SignatureSchemeListExtension.SignatureScheme? selectedSigScheme = null;

            bool selectedOk = crypto.SelectSigAlgoAndCert(
                clientSupportedSignatures.ToArray(),
                clientSupporetdCertSignatures?.Schemes.ToArray(),
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

            //messageIO.ChangeRecordLayerCrypto(crypto, Crypto.RecordLayerKeyType.Handshake);
            messageIO.ChangeRecordLayerWriteCrypto(crypto, crypto.ServerHandshakeTrafficSecret);
            messageIO.ChangeRecordLayerReadCrypto(crypto, crypto.ClientHandshakeTrafficSecret);

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
            bool hasPskExtension = clientHello.TryGetExtension(ExtensionType.PreSharedKey, out _);
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

        private void GREASE(object msg)
        {
            /*  RFC 8701 */

            GreaseInject.ForServer(msg, config.GREASE);
        }
    }
}
