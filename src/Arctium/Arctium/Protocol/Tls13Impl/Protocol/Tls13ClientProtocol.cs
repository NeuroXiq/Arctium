/*
 *  TLS 1.3 Client implementation
 *  Implemented by NeuroXiq 2022
 */

// todo tls13 free memory after connected success

using Arctium.Shared;
using Arctium.Protocol.Tls13.Messages;
// using Arctium.Protocol.Tls13.
using Arctium.Protocol.Tls13;
using Arctium.Protocol.Tls13Impl.Model;
using Arctium.Protocol.Tls13Impl.Model.Extensions;
using Arctium.Protocol.Tls13Impl.Protocol.Helpers;
using Arctium.Standards.X509.X509Cert;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Arctium.Protocol.Tls13Impl.Protocol
{
    internal class Tls13ClientProtocol
    {
        public struct ConnectedInfo
        {
            public bool IsPskSessionResumption;
            public byte[][] ServerCertificates;
            public SupportedGroupExtension.NamedGroup? KeyExchangeNamedGroup;
            public SignatureSchemeListExtension.SignatureScheme? ServerCertificateVerifySignatureScheme;
            public Model.CipherSuite CipherSuite;
            public bool ServerRequestedCertificateInHandshake;
            public ushort? NegotiatedRecordSizeLimitExtension;
            public byte[] ExtensionResultALPN;
            public bool ExtensionResultServerName;

            public byte[][] ClientHandshakeAuthenticationCertificatesSentByClient;
        }

        public byte[] ApplicationDataBuffer { get; private set; }
        public int ApplicationDataLength { get { return applicationDataLength; } }

        public class PostHandshakeAuth
        {
            public ByteBuffer hsctx;
            public CertificateRequest CertificateRequest;
            public X509CertWithKey X509ClientCertificate;


            public PostHandshakeAuth()
            {
                hsctx = new ByteBuffer();
            }

            public void AppendHsContext(byte[] buf, int offs, int len)
            {
                hsctx.Append(buf, offs, len);
            }
        }

        class Context
        {
            public ClientHello ClientHello1;
            public ServerHello HelloRetryRequest;
            public ClientHello ClientHello2;
            public bool ServerRequestedCertificateInHandshake;
            public X509Certificate ServerCertificate;

            public PskTicket[] PskTickets;
            public ServerHello ServerHello;

            public int CH1Length = -1;
            public bool IsPskSessionResumption;

            public byte[][] ServerCertificatesRawBytes { get; internal set; }
            public ushort? NegotiatedRecordSizeLimitExtension { get; internal set; }
            public X509CertWithKey ClientCertificateHandshakeAuthentication { get; internal set; }
            public CertificateRequest HandshakeCertificateRequest { get; internal set; }
            public bool PostHandshakeKeyUpdateOutsideCommandUpdateRequested { get; internal set; }

            // public CertificateRequest PostHandshakeCertificateRequest { get; internal set; }
            // public X509CertWithKey PostHandshakeClientCertificate { get; internal set; }

            public SignatureSchemeListExtension.SignatureScheme? ServerCertificateVerifySignatureScheme;
            public SupportedGroupExtension.NamedGroup? KeyExchangeNamedGroup;
            public byte[] ExtensionALPN_ProtocolSelectedByServer;
            public bool ExtensionServerNameList_ReceivedFromServer;
            public byte[][] ClientHandshakeAuthenticationCertificatesSentByClient;
            public PostHandshakeAuth PostHandshakeAuth;

            public ClientProtocolCommand? CommandAfterFinishedProcessingPostHandshake { get; internal set; }
            public List<ExtensionType> SupportedExtensions = new List<ExtensionType>();
        }

        internal void WaitForAnyProtocolData()
        {
            RunCommandFromOutside(ClientProtocolCommand.Connected_OutsideCommandWaitForAnyProtocolData);
        }

        Context context;
        Tls13ClientConfig config { get { return clientContext.Config; } }
        public ClientProtocolState state { get; private set; }
        Queue<ClientProtocolCommand> commandQueue;
        Crypto crypto;
        Dictionary<SupportedGroupExtension.NamedGroup, byte[]> generatedPrivateKeys;
        MessageIO messageIO;
        Validate validate;
        ClientProtocolCommand currentCommand;
        Tls13ClientContext clientContext;
        ByteBuffer hsctx;

        byte[] writeApplicationDataBuffer;
        long writeApplicationDataOffset;
        long writeApplicationDataLength;
        int applicationDataLength;

        public Tls13ClientProtocol(Stream networkRawStream, Tls13ClientContext clientContext)
        {
            this.clientContext = clientContext;
            context = new Context();
            crypto = new Crypto(Endpoint.Client, null);
            generatedPrivateKeys = new Dictionary<SupportedGroupExtension.NamedGroup, byte[]>();
            hsctx = new ByteBuffer();
            validate = new Validate(new Validate.ValidationErrorHandler(SendAlertFatal));
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
            RunCommandFromOutside(ClientProtocolCommand.Start_Connect);

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
                ClientHandshakeAuthenticationCertificatesSentByClient = context.ClientHandshakeAuthenticationCertificatesSentByClient
            };

            return info;
        }

        public void Close() => RunCommandFromOutside(ClientProtocolCommand.Connected_OutsideCommandClose);

        internal void PostHandshakeKeyUpdate(bool updateRequested)
        {
            context.PostHandshakeKeyUpdateOutsideCommandUpdateRequested = updateRequested;
            RunCommandFromOutside(ClientProtocolCommand.Connected_OutsideCommandExecutePostHandshakeKeyUpdate);
        }

        // private void ProcessCommand(ClientProtocolCommand command)
        // {
        //     commandQueue.Enqueue(command);
        //     ProcessCommand();
        // }

        private void ProcessCommand()
        {
            try
            {
                InnerProcessCommand();

            }
            catch (Tls13ReceivedAlertException e)
            {
                if (e.AlertDescription == AlertDescription.CloseNotify)
                {
                    state = ClientProtocolState.Closed;
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

        private void SendAlertFatal(Tls13AlertException alertException)
        {
            try
            {
                messageIO.WriteAlert(alertException.AlertLevel, alertException.AlertDescription);
            }
            catch
            {
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
                case ClientProtocolCommand.Connected_OutsideCommandExecutePostHandshakeKeyUpdate: Connected_OutsideCommandExecutePostHandshakeKeyUpdate(); break;
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
                case ClientProtocolCommand.PostHandshake_CertificateRequest: PostHandshake_CertificateRequest(); break;
                case ClientProtocolCommand.PostHandshake_NewSessionTicket: PostHandshake_NewSessionTicket(); break;
                case ClientProtocolCommand.PostHandshake_Certificate: PostHandshake_Certificate(); break;
                case ClientProtocolCommand.PostHandshake_CertificateVerify: PostHandshake_CertificateVerify(); break;
                case ClientProtocolCommand.PostHandshake_Finished: PostHandshake_Finished(); break;
                case ClientProtocolCommand.PostHandshake_SendKeyUpdate: PostHandshake_SendKeyUpdate(); break;
                case ClientProtocolCommand.PostHandshake_KeyUpdateReceived: PostHandshake_KeyUpdateReceived(); break;
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
                case ClientProtocolCommand.Handshake_ServerHello: Handshake_ServerHello(); break;
                case ClientProtocolCommand.Handshake_EncryptedExtensions: Handshake_EncryptedExtensions(); break;
                case ClientProtocolCommand.Handshake_CertificateRequest: Handshake_CertificateRequest(); break;
                case ClientProtocolCommand.Handshake_ServerCertificate: Handshake_ServerCertificate(); break;
                case ClientProtocolCommand.Handshake_ServerCertificateVerify: Handshake_ServerCertificateVerify(); break;
                case ClientProtocolCommand.Handshake_ServerFinished: Handshake_ServerFinished(); break;
                case ClientProtocolCommand.Handshake_ClientCertificate: Handshake_ClientCertificate(); break;
                case ClientProtocolCommand.Handshake_ClientCertificateVerify: Handshake_ClientCertificateVerify(); break;
                case ClientProtocolCommand.Handshake_ClientFinished: Handshake_ClientFinished(); break;
                case ClientProtocolCommand.Handshake_HandshakeCompletedSuccessfully: Handshake_HandshakeCompletedSuccessfully(); break;
                case ClientProtocolCommand.Connected_OutsideCommandWaitForAnyProtocolData: Connected_OutsideCommandWaitForAnyProtocolData(); break;
                case ClientProtocolCommand.Connected_OutsideCommandClose: Connected_OutsideCommandClose(); break;
                default: ThrowEx("invalid command for this state"); break;
            }
        }

        private void Connected_OutsideCommandClose()
        {
            if (state == ClientProtocolState.Closed) return;

            messageIO.WriteAlert(AlertLevel.Warning, AlertDescription.CloseNotify);
            state = ClientProtocolState.Closed;
        }

        private void Connected_OutsideCommandWaitForAnyProtocolData()
        {
            var recordType = messageIO.BufferAnyRecordType();

            if (recordType == ContentType.Handshake)
            {
                context.CommandAfterFinishedProcessingPostHandshake = null;
                commandQueue.Enqueue(ClientProtocolCommand.Connected_ReceivedPostHandshakeMessage);
            }
        }

        private void ThrowEx(string msg)
        {
            throw new Tls13Exception(msg);

        }

        public void LoadApplicationData() => RunCommandFromOutside(ClientProtocolCommand.Connected_ReadApplicationData);

        public void WriteApplicationData(byte[] buffer, long offset, long length)
        {
            writeApplicationDataBuffer = buffer;
            writeApplicationDataOffset = offset;
            writeApplicationDataLength = length;

            RunCommandFromOutside(ClientProtocolCommand.Connected_WriteApplicationData);

            // free memory (do not lock buffer from external source)
            writeApplicationDataBuffer = null;
            writeApplicationDataOffset = -1;
            writeApplicationDataLength = -1;
        }

        private void RunCommandFromOutside(ClientProtocolCommand command)
        {
            commandQueue.Enqueue(command);
            ProcessCommand();
        }

        private void Connected_ReadApplicationData()
        {
            if (messageIO.TryLoadApplicationData(ApplicationDataBuffer, 0, out applicationDataLength))
            {
                return;
            }

            context.CommandAfterFinishedProcessingPostHandshake = ClientProtocolCommand.Connected_ReadApplicationData;
            commandQueue.Enqueue(ClientProtocolCommand.Connected_ReceivedPostHandshakeMessage);
        }

        private void PostHandshake_KeyUpdateReceived()
        {
            var keyUpdate = messageIO.ReadHandshakeMessage<KeyUpdate>();

            messageIO.KeyUpdateForReading(crypto);

            if (keyUpdate.RequestUpdate == KeyUpdate.KeyUpdateRequest.UpdateRequested)
            {
                commandQueue.Enqueue(ClientProtocolCommand.PostHandshake_SendKeyUpdate);
            }
            else
            {
                commandQueue.Enqueue(ClientProtocolCommand.PostHandshake_FinishedProcessingPostHandshakeMessages);
            }
        }

        private void PostHandshake_SendKeyUpdate()
        {
            var type = context.PostHandshakeKeyUpdateOutsideCommandUpdateRequested ?
                KeyUpdate.KeyUpdateRequest.UpdateRequested : KeyUpdate.KeyUpdateRequest.NotRequested;

            var keyUpdate = new KeyUpdate(type);

            messageIO.WriteHandshake(keyUpdate);

            messageIO.KeyUpdateForWriting(crypto);

            commandQueue.Enqueue(ClientProtocolCommand.PostHandshake_FinishedProcessingPostHandshakeMessages);
        }

        private void Connected_OutsideCommandExecutePostHandshakeKeyUpdate()
        {
            state = ClientProtocolState.PostHandshake;
            context.CommandAfterFinishedProcessingPostHandshake = null;
            commandQueue.Enqueue(ClientProtocolCommand.PostHandshake_SendKeyUpdate);
        }

        private void PostHandshake_FinishedProcessingPostHandshakeMessages()
        {
            state = ClientProtocolState.Connected;

            if (context.CommandAfterFinishedProcessingPostHandshake.HasValue)
            {
                commandQueue.Enqueue(context.CommandAfterFinishedProcessingPostHandshake.Value);
                context.CommandAfterFinishedProcessingPostHandshake = null;
            }
        }

        private void PostHandshake_ProcessPostHandshakeMessage()
        {
            var messageType = messageIO.BufferHandshakeMessage();

            switch (messageType)
            {
                case HandshakeType.NewSessionTicket: commandQueue.Enqueue(ClientProtocolCommand.PostHandshake_NewSessionTicket); break;
                case HandshakeType.CertificateRequest: commandQueue.Enqueue(ClientProtocolCommand.PostHandshake_CertificateRequest); break;
                case HandshakeType.KeyUpdate: commandQueue.Enqueue(ClientProtocolCommand.PostHandshake_KeyUpdateReceived); break;
                default:
                    validate.Other.AlertFatal(AlertDescription.UnexpectedMessage, $"Unexpected post handshake message (redeived: '{messageType}') or not supported");
                    break;
            }
        }

        private void PostHandshake_Finished()
        {
            var finishedVer = crypto.ComputeFinishedVerData(context.PostHandshakeAuth.hsctx, Endpoint.Client, true);

            var finished = new Finished(finishedVer);

            messageIO.WriteHandshake(finished);

            messageIO.OnHandshakeReadWrite -= context.PostHandshakeAuth.AppendHsContext;
            context.PostHandshakeAuth = null;

            commandQueue.Enqueue(ClientProtocolCommand.PostHandshake_FinishedProcessingPostHandshakeMessages);
        }

        private void PostHandshake_CertificateVerify()
        {
            var signatureScheme = crypto.SelectSignatureSchemeForCertificate(context.PostHandshakeAuth.X509ClientCertificate.Certificate, config.SignatureSchemes);

            if (!signatureScheme.HasValue) throw new Exception("Something is wrong with client certificate, signature not supported or not configured");

            var signature = crypto.GenerateCertificateVerifySignature(context.PostHandshakeAuth.hsctx, context.PostHandshakeAuth.X509ClientCertificate, signatureScheme.Value, Endpoint.Client);

            var certVerify = new CertificateVerify(signatureScheme.Value, signature);

            messageIO.WriteHandshake(certVerify);

            commandQueue.Enqueue(ClientProtocolCommand.PostHandshake_Finished);
        }

        private void PostHandshake_Certificate()
        {
            var certificateToSend = clientContext.PostHandshakeClientAuthenticationGetCertificate(context.PostHandshakeAuth.CertificateRequest);

            if (certificateToSend.ClientCertificate == null)
            {
                var emptyCert = new Certificate(context.PostHandshakeAuth.CertificateRequest.CertificateRequestContext, new CertificateEntry[0]);
                messageIO.WriteHandshake(emptyCert);

                commandQueue.Enqueue(ClientProtocolCommand.PostHandshake_Finished);
                return;
            }

            List<CertificateEntry> entries = new List<CertificateEntry>();

            entries.Add(new CertificateEntry(null, X509Util.X509CertificateToDerEncodedBytes(certificateToSend.ClientCertificate.Certificate), new Extension[0]));
            entries.AddRange(certificateToSend.ParentCertificates.Select(c => new CertificateEntry(null, X509Util.X509CertificateToDerEncodedBytes(c), new Extension[0])));

            var cert = new Certificate(context.PostHandshakeAuth.CertificateRequest.CertificateRequestContext, entries.ToArray());

            context.PostHandshakeAuth.X509ClientCertificate = certificateToSend.ClientCertificate;

            messageIO.WriteHandshake(cert);

            commandQueue.Enqueue(ClientProtocolCommand.PostHandshake_CertificateVerify);
        }

        private void PostHandshake_CertificateRequest()
        {
            validate.Certificate.AlertFatal(
                config.PostHandshakeClientAuthentication == null,
                AlertDescription.UnexpectedMessage,
                "Server send client authentication, this is unexpected because client authentication was not configured and not supported with current instance");

            // turn on handshake context to compute certificate verify
            context.PostHandshakeAuth = new PostHandshakeAuth();
            context.PostHandshakeAuth.AppendHsContext(hsctx.Buffer, 0, hsctx.DataLength);

            messageIO.OnHandshakeReadWrite += context.PostHandshakeAuth.AppendHsContext;

            var certRequest = messageIO.ReadHandshakeMessage<CertificateRequest>();
            context.PostHandshakeAuth.CertificateRequest = certRequest;

            commandQueue.Enqueue(ClientProtocolCommand.PostHandshake_Certificate);
        }

        private void PostHandshake_NewSessionTicket()
        {
            var ticket = messageIO.ReadHandshakeMessage<NewSessionTicket>();
            clientContext.SaveTicket(ticket.Ticket,
                ticket.TicketNonce,
                crypto.ResumptionMasterSecret,
                ticket.TicketLifetime,
                ticket.TicketAgeAdd,
                crypto.SelectedCipherSuiteHashFunctionId);

            commandQueue.Enqueue(ClientProtocolCommand.PostHandshake_FinishedProcessingPostHandshakeMessages);
        }

        private void Connected_WriteApplicationData()
        {
            messageIO.WriteApplicationData(writeApplicationDataBuffer, writeApplicationDataOffset, writeApplicationDataLength);
        }

        private void Connected_ReceivedPostHandshakeMessage()
        {
            state = ClientProtocolState.PostHandshake;
            commandQueue.Enqueue(ClientProtocolCommand.PostHandshake_ProcessPostHandshakeMessage);
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

            messageIO.WriteHandshake(finished);

            crypto.SetupResumptionMasterSecret(hsctx);

            // messageIO.ChangeRecordLayerCrypto(crypto, this.);
            messageIO.ChangeRecordLayerWriteCrypto(crypto, crypto.ClientApplicationTrafficSecret0);
            messageIO.OnHandshakeReadWrite -= MessageIO_OnHandshakeReadWrite;
            messageIO.SetBackwardCompatibilityMode(false, false);

            commandQueue.Enqueue(ClientProtocolCommand.Handshake_HandshakeCompletedSuccessfully);
        }

        private void Handshake_ClientCertificateVerify()
        {
            Validation.ThrowInternal(context.ClientCertificateHandshakeAuthentication == null);

            var clientCertWithKey = context.ClientCertificateHandshakeAuthentication;

            var schemeForCert = crypto.SelectSignatureSchemeForCertificate(clientCertWithKey.Certificate, config.SignatureSchemes);

            if (!schemeForCert.HasValue)
            {
                string errortext = "Something is wrong with client certificate. " +
                    "This is impossible to generate signature using current configuration during client authentication. " +
                    "Potentional reason is that current configuration for 'SignatureSchemes' does not match with current " +
                    " X509Client Certificate configuration. Probably client certificate allows to sign data with other " +
                    "Signature than current configuration allows. Try to change configuration of 'SignatureScheme' to " +
                    "include client certificate public key";

                validate.Handshake.Throw(true, errortext);
            }


            byte[] clientCertVerify = crypto.GenerateCertificateVerifySignature(hsctx, clientCertWithKey, schemeForCert.Value, Endpoint.Client);
            var certVerify = new CertificateVerify(schemeForCert.Value, clientCertVerify);
            messageIO.WriteHandshake(certVerify);

            commandQueue.Enqueue(ClientProtocolCommand.Handshake_ClientFinished);
        }

        private void Handshake_ClientCertificate()
        {
            List<CertificateEntry> entries = new List<CertificateEntry>();
            bool sentCertVerify = false;
            context.ClientHandshakeAuthenticationCertificatesSentByClient = new byte[0][];
            var certs = clientContext.HandshakeClientAuthenticationGetCertificate(context.HandshakeCertificateRequest);

            if (certs != null)
            {
                if (certs.ClientCertificate != null)
                {
                    sentCertVerify = true;
                    context.ClientCertificateHandshakeAuthentication = certs.ClientCertificate;

                    entries.Add(new CertificateEntry(null, X509Util.X509CertificateToDerEncodedBytes(certs.ClientCertificate.Certificate), new Extension[0]));
                    entries.AddRange(certs.ParentCertificates.Select(p => new CertificateEntry(null, X509Util.X509CertificateToDerEncodedBytes(p), new Extension[0])));

                    context.ClientHandshakeAuthenticationCertificatesSentByClient = entries.Select(e => e.CertificateEntryRawBytes).ToArray();
                }
            }

            var echoCertReqContext = context.HandshakeCertificateRequest.CertificateRequestContext;
            var certificate = new Certificate(echoCertReqContext, entries.ToArray());
            messageIO.WriteHandshake(certificate);

            if (sentCertVerify) commandQueue.Enqueue(ClientProtocolCommand.Handshake_ClientCertificateVerify);
            else commandQueue.Enqueue(ClientProtocolCommand.Handshake_ClientFinished);
        }

        private void Handshake_ServerFinished()
        {
            var verdata = crypto.ComputeFinishedVerData(hsctx, Endpoint.Server);
            var finished = messageIO.ReadHandshakeMessage<Finished>();

            validate.Finished.AlertFatal(!MemOps.Memcmp(verdata, finished.VerifyData), AlertDescription.DecryptError, "server finished verify data invalid");

            crypto.SetupMasterSecret(hsctx);
            messageIO.ChangeRecordLayerReadCrypto(crypto, crypto.ServerApplicationTrafficSecret0);

            if (context.ServerRequestedCertificateInHandshake) commandQueue.Enqueue(ClientProtocolCommand.Handshake_ClientCertificate);
            else commandQueue.Enqueue(ClientProtocolCommand.Handshake_ClientFinished);
        }

        private void Handshake_ServerCertificateVerify()
        {
            int dataLengthToSign = hsctx.DataLength;
            var certVerify = messageIO.ReadHandshakeMessage<CertificateVerify>();
            validate.CertificateVerify.GeneralValidate(context.ClientHello1, certVerify);

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


            if (config.ExtensionSignatureAlgorithmsCert != null)
            {
                // TOOD tls13
                // not sure what to do with this, not so simple (need parent) to determine
                // server certificate exact type, e.g. check if signature is secp256r1Sha256
                // not stored in certificate received from server. 
            }


            commandQueue.Enqueue(ClientProtocolCommand.Handshake_ServerCertificateVerify);
        }

        private void Handshake_CertificateRequest()
        {
            var certReq = messageIO.ReadHandshakeMessage<CertificateRequest>();
            context.HandshakeCertificateRequest = certReq;

            commandQueue.Enqueue(ClientProtocolCommand.Handshake_ServerCertificate);
        }

        private void Handshake_EncryptedExtensions()
        {
            var encryptedExt = messageIO.ReadHandshakeMessage<EncryptedExtensions>();
            validate.EncryptedExtensions.General(encryptedExt, context.ClientHello1 ?? context.ClientHello1);

            foreach (var ext in encryptedExt.Extensions)
            {
                validate.EncryptedExtensions.AlertFatal(
                    !context.SupportedExtensions.Contains(ext.ExtensionType),
                    AlertDescription.Illegal_parameter,
                    "server sent not offered extension (not supported extension)");

                switch (ext.ExtensionType)
                {
                    case ExtensionType.RecordSizeLimit:
                        var recordSizeLimitFromServer = ext as RecordSizeLimitExtension;
                        // todo tls13 not sure if this is correct (condition in 'if' for this block), can server send recordsizelimit if client did not?
                        // answer: probably not (server must not sent extensions if not offered in cliehthello)
                        ushort min = Math.Min(config.ExtensionRecordSizeLimit.Value, recordSizeLimitFromServer.RecordSizeLimit);
                        context.NegotiatedRecordSizeLimitExtension = min;
                        messageIO.SetRecordSizeLimit(min);
                        break;
                    case ExtensionType.ServerName:
                        context.ExtensionServerNameList_ReceivedFromServer = true;
                        break;
                    case ExtensionType.ApplicationLayerProtocolNegotiation:
                        var alpnServer = ext as ProtocolNameListExtension;
                        context.ExtensionALPN_ProtocolSelectedByServer = alpnServer.ProtocolNamesList[0];
                        break;
                    default:
                        validate.EncryptedExtensions.AlertFatal(AlertDescription.UnsupportedExtension, "Invalid extension for EncryptedExtensions message");
                        break;
                }
            }

            if (context.IsPskSessionResumption) commandQueue.Enqueue(ClientProtocolCommand.Handshake_ServerFinished);
            else if (messageIO.BufferHandshakeMessage() == HandshakeType.CertificateRequest)
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
            var sh = context.ServerHello;

            validate.ServerHello.GeneralServerHelloValidate(context.ClientHello2, sh, config.CipherSuites);
            ServerSupportedVersionsExtension version = null;
            KeyShareEntry serverKeyShare = null;
            PreSharedKeyServerHelloExtension preSharedKeySh = null;

            foreach (var ext in sh.Extensions)
            {
                validate.ServerHello.AlertFatal(
                    !context.SupportedExtensions.Contains(ext.ExtensionType),
                    AlertDescription.UnsupportedExtension,
                    $"not supported extension {ext.ExtensionType}");

                switch (ext.ExtensionType)
                {
                    case ExtensionType.SupportedVersions:
                        version = ext as ServerSupportedVersionsExtension;
                        break;
                    case ExtensionType.KeyShare:
                        serverKeyShare = (ext as KeyShareServerHelloExtension).ServerShare;
                        break;
                    case ExtensionType.PreSharedKey:
                        preSharedKeySh = ext as PreSharedKeyServerHelloExtension;
                        break;
                    default:
                        validate.ServerHello.AlertFatal(AlertDescription.UnsupportedExtension, $"not supported extension {ext.ExtensionType}");
                        break;
                }
            }

            validate.ServerHello.AlertFatal(version == null, AlertDescription.MissingExtension, "missing version extension");
            validate.ServerHello.AlertFatal(version.SelectedVersion != 0x0304, AlertDescription.Illegal_parameter, "not supported version (other than 0x0304)");
            validate.ServerHello.AlertFatal(!config.CipherSuites.Contains(sh.CipherSuite), AlertDescription.Illegal_parameter, "server selected not supported ciphersuite");

            byte[] psk = null;

            crypto.SelectCipherSuite(sh.CipherSuite);

            // todo check if server response is correct compared to sended CH (check if this class send keyexchangemode.psk_ke)
            // todo server could select KeyExchangeMode_ke (not dhe), need to implement this
            if (serverKeyShare == null)
            {
                validate.Handshake.AlertFatal(AlertDescription.Illegal_parameter, "server tries to psk_ke but this is not supported");
            }
            else
            {
                context.KeyExchangeNamedGroup = serverKeyShare.NamedGroup;
                crypto.ComputeSharedSecret(serverKeyShare.NamedGroup, generatedPrivateKeys[serverKeyShare.NamedGroup], serverKeyShare.KeyExchangeRawBytes);
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

            // messageIO.ChangeRecordLayerCrypto(crypto, Crypto.RecordLayerKeyType.Handshake);
            messageIO.ChangeRecordLayerReadCrypto(crypto, crypto.ServerHandshakeTrafficSecret);
            messageIO.ChangeRecordLayerWriteCrypto(crypto, crypto.ClientHandshakeTrafficSecret);

            commandQueue.Enqueue(ClientProtocolCommand.Handshake_EncryptedExtensions);
        }

        private void Handshake_ClientHello2()
        {
            // process HelloRetryRequst
            // 1. send everything what was send in clienthello1 (but skip 'key share' sended in clienthello1 because server selected, this is reason of this situation here)
            // 2. get keyshareserverhelloretry from server and send key share which server wants

            validate.HelloRetryRequest.GeneralValidate(context.ClientHello1, context.HelloRetryRequest, config.CipherSuites, config.ExtensionSupportedGroups.InternalNamedGroups);
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

            if (cookieFromServer != null) extensions2.Add(cookieFromServer);

            extensions2.Add(new KeyShareClientHelloExtension(new KeyShareEntry[] { new KeyShareEntry(serverKeyShare.SelectedGroup, keyShareToSendRawBytes) }));

            context.ClientHello2 = new ClientHello(context.ClientHello1.Random,
                context.ClientHello1.LegacySessionId,
                context.ClientHello1.CipherSuites.ToArray(),
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

            context.SupportedExtensions.Add(ExtensionType.PreSharedKey);
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
            Tls13Impl.Model.CipherSuite[] suites = config.CipherSuites;
            List<KeyShareEntry> generatedKeysToExchange = new List<KeyShareEntry>();
            ClientHello clientHello;

            GlobalConfig.RandomGeneratorCryptSecure(random, 0, random.Length);
            GlobalConfig.RandomGeneratorCryptSecure(sesId, 0, sesId.Length);

            List<Extension> extensions = new List<Extension>
            {
                new ClientSupportedVersionsExtension(new ushort[] { 0x0304 }),
                new SignatureSchemeListExtension(config.SignatureSchemes, ExtensionType.SignatureAlgorithms),
                new PreSharedKeyExchangeModeExtension(new PreSharedKeyExchangeModeExtension.PskKeyExchangeMode[] { PreSharedKeyExchangeModeExtension.PskKeyExchangeMode.PskDheKe })
            };

            var supportedGroups = clientContext.GetExtension_SupportedGroups();
            Validation.ThrowInternal(supportedGroups == null || supportedGroups.NamedGroupList.Count == 0);
            extensions.Add(supportedGroups);

            var certAuthorities = clientContext.GetExtension_CertificateAuthorities();

            if (certAuthorities != null) extensions.Add(certAuthorities);

            if (config.PostHandshakeClientAuthentication != null)
            {
                extensions.Add(new PostHandshakeAuthExtension());
            }

            if (config.ExtensionSignatureAlgorithmsCert != null)
            {
                extensions.Add(new SignatureSchemeListExtension(
                    config.ExtensionSignatureAlgorithmsCert.SupportedSignatureSchemesCert,
                    ExtensionType.SignatureAlgorithmsCert));
            }

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

            foreach (var toSendInKeyShare in config.ExtensionKeyShare.InternalNamedGroups)
            {
                byte[] keyShareToSendRawBytes, privateKey;

                crypto.GeneratePrivateKeyAndKeyShareToSend(toSendInKeyShare, out keyShareToSendRawBytes, out privateKey);
                generatedPrivateKeys[toSendInKeyShare] = privateKey;

                generatedKeysToExchange.Add(new KeyShareEntry(toSendInKeyShare, keyShareToSendRawBytes));
            }

            extensions.Add(new KeyShareClientHelloExtension(generatedKeysToExchange.ToArray()));
            context.SupportedExtensions.AddRange(extensions.Select(e => e.ExtensionType));

            clientHello = new ClientHello(random, sesId, suites, extensions);
            GREASE(clientHello);
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

        private void GREASE(ClientHello message)
        {
            GreaseInject.ClientHello(message, config.GREASE);
        }
    }
}
