/* FOLLOWING SPECIFICATION GOINT TO BE IMPLEMENTED: 
 * 
Internet Engineering Task Force (IETF) E. Rescorla
Request for Comments: 8446 Mozilla
Obsoletes: 5077, 5246, 6961 August 2018
Updates: 5705, 6066
Category: Standards Track
ISSN: 2070-1721

 The Transport Layer Security (TLS) Protocol Version 1.3
Abstract
 This document specifies version 1.3 of the Transport Layer Security
 (TLS) protocol. TLS allows client/server applications to communicate
 over the Internet in a way that is designed to prevent eavesdropping,
 tampering, and message forgery.
 This document updates RFCs 5705 and 6066, and obsoletes RFCs 5077,
 5246, and 6961. This document also specifies new requirements for
 TLS 1.2 implementations.
 */

/* This class doesn't have special logic or meaning,
 * it just throws exceptions and perform validation of input.
 * This is a centralized place to store all exceptions/validations
 * 
 */


using Arctium.Standards.Connection.Tls.Tls13.API;
using Arctium.Standards.Connection.Tls.Tls13.Model;
using Arctium.Standards.Connection.Tls.Tls13.Model.Extensions;
using Arctium.Shared.Helpers.Binary;
using System;
using System.Collections.Generic;
using System.Linq;
using Arctium.Shared.Other;
using Arctium.Shared.Helpers;

namespace Arctium.Standards.Connection.Tls.Tls13.Protocol
{
    class Validate
    {
        const string Label_ServerHello = "ServerHello";
        const string Label_ClientHello = "ClientHello";
        const string Label_ExtensionMaxFragmentLength = "Extension_MaxFragmentLength";
        const string Label_EncryptedExtensions = "EncryptedExtensions";


        public RecordLayerValidate RecordLayer { get; private set; }
        public HandshakeValidate Handshake { get; private set; }
        public ExtensionsValidate Extensions { get; private set; }
        public CertificateValidate Certificate { get; private set; }
        public ClientHelloValidate ClientHello { get; private set; }
        public FinishedValidate Finished { get; private set; }
        public ServerHelloValidate ServerHello { get; private set; }
        public NewSessionTicketValidate NewSessionTicket { get; private set; }
        public HelloRetryRequestValidate HelloRetryRequest { get; private set; }
        public DefaultNamedValidate Extension_MaxFragmentLength { get; private set; }
        public EncryptedExtensionsValidate EncryptedExtensions { get; private set; }

        public Validate()
        {
            var errorHandler = new ValidationErrorHandler();
            this.RecordLayer = new RecordLayerValidate(errorHandler);
            this.Handshake = new HandshakeValidate(errorHandler);
            this.Extensions = new ExtensionsValidate(errorHandler);
            this.ClientHello = new ClientHelloValidate(errorHandler);
            Finished = new FinishedValidate(errorHandler);
            ServerHello = new ServerHelloValidate(errorHandler);
            NewSessionTicket = new NewSessionTicketValidate(errorHandler);
            HelloRetryRequest = new HelloRetryRequestValidate(errorHandler);
            Extension_MaxFragmentLength = new DefaultNamedValidate(errorHandler, Label_ExtensionMaxFragmentLength);
            EncryptedExtensions = new EncryptedExtensionsValidate(errorHandler);

            Certificate = new CertificateValidate(errorHandler);
        }

        public class DefaultNamedValidate : ValidateBase
        {
            public DefaultNamedValidate(ValidationErrorHandler handler, string messageName) : base(handler, messageName)
            {
            }
        }

        public class NewSessionTicketValidate : ValidateBase
        {
            public NewSessionTicketValidate(ValidationErrorHandler handler) : base(handler, "NewSessionTicket")
            {
            }
        }

        public class ValidationErrorHandler
        {
            public void Throw(string messageName, string fieldName, string error)
            {
                Throw(FormatMessage(messageName, fieldName, error));
            }

            public void ThrowAlertFatal(AlertDescription alert, string messageName, string errorText)
            {
                throw new Tls13AlertException(AlertLevel.Fatal, alert, messageName, null, errorText);
            }

            public void ThrowAlertFatal(AlertDescription alert, string messageName, string field, string error)
            {
                throw new Tls13AlertException(AlertLevel.Fatal, alert, messageName, field, error);
            }

            public void Throw(string error)
            {
                throw new Tls13Exception(null, null, error);
            }

            string FormatMessage(string messageName, string fieldName, string error)
            {
                messageName = messageName ?? string.Empty;
                fieldName = fieldName ?? string.Empty;
                error = error ?? string.Empty;

                return $"MESSAGE: {messageName}, FIELD: {fieldName}, Error: {error}";
            }
        }
        public class ValidateBase
        {
            private ValidationErrorHandler handler;
            string messageName;

            public ValidateBase(ValidationErrorHandler handler, string messageName)
            {
                this.messageName = messageName;
                this.handler = handler;
            }

            public void Throw(bool condition, string error) => Throw(condition, null, error);

            public void AlertFatalDecodeError(bool condition, string field, string error)
            {
                if (condition)
                {
                    handler.ThrowAlertFatal(AlertDescription.DecodeError, messageName, field, error);
                }
            }

            public void AlertFatal(AlertDescription description, string errorText) => AlertFatal(true, description, errorText);

            public void AlertFatal(bool shouldThrow, AlertDescription alertDescription, string errorText)
            {
                if (shouldThrow) handler.ThrowAlertFatal(alertDescription, messageName, errorText);
            }

            public void AlertFatal_IllegalParameter(string errorText) => AlertFatal(true, AlertDescription.Illegal_parameter, errorText);

            public void Throw(bool condition, string field, string error)
            {
                if (condition) handler.Throw(messageName, null, error);
            }
        }

        public class HelloRetryRequestValidate : ValidateBase
        {
            public HelloRetryRequestValidate(ValidationErrorHandler handler) : base(handler, "HelloRetryRequest")
            {
            }

            public void GeneralValidate(ClientHello clientHello1, ServerHello helloRetry)
            {
                AlertFatal(!clientHello1.CipherSuites.Contains(helloRetry.CipherSuite), AlertDescription.Illegal_parameter, "cipher suite from server not match clienthello");

                var keyShareHrr = helloRetry.Extensions.FirstOrDefault(ext => ext.ExtensionType == ExtensionType.KeyShare) as KeyShareHelloRetryRequestExtension;
                var clientGroups = clientHello1.Extensions.First(ext => ext.ExtensionType == ExtensionType.SupportedGroups) as SupportedGroupExtension;

                AlertFatal(keyShareHrr == null, AlertDescription.Illegal_parameter, "server didnt send keysharehelloretryrequest or send keyshare with keyexchange bytes instead of retry");
                AlertFatal(!clientGroups.NamedGroupList.Contains(keyShareHrr.SelectedGroup), AlertDescription.Illegal_parameter, "server selected group not listed in clienthello");
            }
        }

        public class FinishedValidate : ValidateBase
        {
            public FinishedValidate(ValidationErrorHandler handler) : base(handler, "Finished")
            {
            }

            public void FinishedSigValid(bool isSignatureValid)
                => AlertFatal(!isSignatureValid, AlertDescription.DecryptError, "invalid finished signature");
        }

        public class CertificateRequestValidate : ValidateBase
        {
            public CertificateRequestValidate(ValidationErrorHandler handler) : base(handler, "CertificateRequest")
            {
            }

            public void General(CertificateRequest certificate)
            {
                ExtensionType[] validCertificateExtTypes = new ExtensionType[]
                    {
                        ExtensionType.StatusRequest, ExtensionType.SupportedGroups,
                    };
            }
        }

        public class EncryptedExtensionsValidate : ValidateBase
        {
            ExtensionsValidate extensionsValidate;

            public EncryptedExtensionsValidate(ValidationErrorHandler handler) : base(handler, Label_EncryptedExtensions)
            {
                extensionsValidate = new ExtensionsValidate(handler, Label_EncryptedExtensions);
            }

            public void General(EncryptedExtensions encryptedExtensions, ClientHello clientHello2Or1ThatWasSend)
            {
                var ch = clientHello2Or1ThatWasSend;
                extensionsValidate.SharedExtensionsValidate(encryptedExtensions.Extensions.ToList(), HandshakeType.EncryptedExtensions);

                var serverRecordSizeLimit = encryptedExtensions.Extensions.FirstOrDefault(e => e.ExtensionType == ExtensionType.RecordSizeLimit) as RecordSizeLimitExtension;
                var clientRecordSizeLimit = ch.Extensions.FirstOrDefault(e => e.ExtensionType == ExtensionType.RecordSizeLimit) as RecordSizeLimitExtension;

                if (serverRecordSizeLimit != null && clientRecordSizeLimit != null)
                {
                    AlertFatal(serverRecordSizeLimit.RecordSizeLimit > clientRecordSizeLimit.RecordSizeLimit,
                        AlertDescription.Illegal_parameter,
                        "Value of recordsizelimit from server exceed recordsizelimit extensions from client " + 
                        "(that was sent from client to server)");
                }
            }
        }

        public class ServerHelloValidate : ValidateBase
        {
            ExtensionsValidate extensionsValidate;

            public ServerHelloValidate(ValidationErrorHandler handler) : base(handler, Label_ServerHello)
            {
                extensionsValidate = new ExtensionsValidate(handler, Label_ServerHello);
            }

            public void GeneralServerHelloValidate(ClientHello clientHelloThatWasSend, ServerHello hello)
            {
                extensionsValidate.GeneralValidateServerHelloExtensions(hello);

                // alpn
                var alpn = hello.Extensions.FirstOrDefault(e => e.ExtensionType == ExtensionType.ApplicationLayerProtocolNegotiation) as ProtocolNameListExtension;
                if (alpn != null)
                {
                    ProtocolNameListExtension sentByClient;
                    bool alpnWasSent = clientHelloThatWasSend.TryGetExtension<ProtocolNameListExtension>(ExtensionType.ApplicationLayerProtocolNegotiation, out var alpnThatWasSend);

                    if (!alpnWasSent) AlertFatal(AlertDescription.UnsupportedExtension, "received alpn but client didn not sent this extension");
                    if (alpn.ProtocolNamesList.Length == 0) AlertFatal(AlertDescription.Illegal_parameter, "zero length of alpn in serverhello response");
                    if (alpn.ProtocolNamesList.Length != 1) AlertFatal(AlertDescription.Illegal_parameter, "alpn server must select one protocol but received more than one in the list");
                    bool selectedWhatWasSent = alpnThatWasSend.ProtocolNamesList.Any(wasSent => MemOps.Memcmp(wasSent, alpn.ProtocolNamesList[0]));

                    AlertFatal(selectedWhatWasSent, AlertDescription.Illegal_parameter, "server alpn response does not math what was sent by client");
                }
            }
        }

        public class ClientHelloValidate : ValidateBase
        {
            ExtensionsValidate extensionsValidate;

            public ClientHelloValidate(ValidationErrorHandler handler) : base(handler, Label_ClientHello)
            {
                extensionsValidate = new ExtensionsValidate(handler, Label_ClientHello);
            }

            internal void GeneralValidateClientHello(ClientHello clientHello)
            {
                extensionsValidate.GeneralValidateClientHelloExtensions(clientHello);
            }

            internal void SignatureSchemesNotSupported(bool sthrow) =>
                AlertFatal(sthrow, AlertDescription.HandshakeFailure, "signature scheme list extension does not match with supported one or with current instance configuration"); 

            internal void MissingSignatureAlgorithmsExtension(bool throwEx) => AlertFatal(throwEx, AlertDescription.MissingExtension, "missing signature scheme list extension");
        }

        public class CertificateValidate : ValidateBase
        {
            public CertificateValidate(ValidationErrorHandler handler) : base(handler, "Certificate")
            {
            }

            public void General(Certificate certificate)
            {
                ExtensionType[] validCertificateExtTypes = new ExtensionType[]
                    {
                        ExtensionType.StatusRequest,
                    };
            }

            internal void CertificateEntry_CertificateTypeMinLen(int certDataLen)
            {
                Throw(certDataLen < 0, "rawpublickey OR x509", "minimum vector length is 1");
            }

            internal void ValidateCertificateValidationCallbackSuccess(ServerCertificateValidionResult validationResult)
            {
                if (validationResult == ServerCertificateValidionResult.Success) return;


                AlertDescription alert = AlertDescription.AccessDenied;

                switch (validationResult)
                {
                    case ServerCertificateValidionResult.Invalid_UnknownCA: alert = AlertDescription.UnknownCa;  break;
                    case ServerCertificateValidionResult.Invalid_OtherReason: alert = AlertDescription.CertificateUnknown;  break;
                    case ServerCertificateValidionResult.Invalid_BadCertificateStatusResponse: alert = AlertDescription.BadCertificateStatusResponse; break;
                    case ServerCertificateValidionResult.Invalid_CertificateUnknown: alert = AlertDescription.CertificateUnknown;  break;
                    case ServerCertificateValidionResult.Invalid_CertificateExpired: alert = AlertDescription.CertificateExpired;  break;
                    case ServerCertificateValidionResult.Invalid_CertificateRevoked: alert = AlertDescription.CertificateRevoked;  break;
                    case ServerCertificateValidionResult.Invalid_UnsupportedCertificate: alert = AlertDescription.UnsupportedCertificate;  break;
                    case ServerCertificateValidionResult.Invalid_BadCertificate: alert = AlertDescription.BadCertificate;  break;
                    default: Validation.NotSupported(); break;
                }

                AlertFatal(true, alert, "CertificateValidationCallback returned false, certificate is invalid by current configuration.");
            }
        }

        public class RecordLayerValidate : ValidateBase
        {
            const ushort LegacyRecordVersion = 0x0303;
            const ushort LegacyRecordVersion0301 = 0x0301;
            const ushort MaxRecordLength = 2 << 14;

            public RecordLayerValidate(ValidationErrorHandler handler) : base(handler, "Record Layer")
            {
            }

            public void AEADAuthTagInvalid(bool isAuthTagValid) => AlertFatal(!isAuthTagValid, AlertDescription.BadRecordMac, "Decrypted record with invalid authentication tag");

            public void Length(ushort receivedLength, ushort configuredMaxPlaintextLength)
            {
            }

            private void Throw(string msg, params object[] args)
            {
                string error = string.Format("Record Layer: {0}", string.Format(msg, args));
                throw new Tls13Exception("","",error);
            }

            internal void ValidateRecord(bool isRecordEncrypted,
                ushort length,
                byte contentType,
                ushort protocolVersion,
                ushort configuredMaxPlaintextRecordLength,
                bool compatibilityAllowRecordLayerVersionLower0x0303)
            {

                if (contentType != (byte)ContentType.Alert &&
                   contentType != (byte)ContentType.ApplicationData &&
                   contentType != (byte)ContentType.ChangeCipherSpec &&
                   contentType != (byte)ContentType.Handshake)
                {
                    Throw(string.Format("Received record with unrecognized content type value. Received content Type value: {0}", contentType));
                }

                bool isValid = protocolVersion == LegacyRecordVersion ||
                    (compatibilityAllowRecordLayerVersionLower0x0303 && protocolVersion < LegacyRecordVersion);

                if (isValid) return;

                Throw("Received record with invalid LegacyRecordVersion. Expected: {0} but current: {1}",
                    BinConverter.ToStringHex(LegacyRecordVersion),
                    BinConverter.ToStringHex(protocolVersion));

                int maxLength = configuredMaxPlaintextRecordLength;

                if (isRecordEncrypted) maxLength += Tls13Const.RecordLayer_MaxExpansionAfterEncryptionForAnyCipher;

                if (length > maxLength)
                {
                    string msg = string.Format(
                        "Received record with length exceeded maximum length. " +
                         "expected max length: {0}, received length: {1} (max received length can be configured), is record encrypted: {2}",
                         maxLength, length, isRecordEncrypted);

                    AlertFatal(AlertDescription.RecordOverflow, msg);
                }
            }


        }

        public class HandshakeValidate : ValidateBase
        {
            public HandshakeValidate(ValidationErrorHandler handler) : base(handler, "<Generic-Handshake>")
            {
            }

            public void ValidHandshakeType(HandshakeType handshakeType)
            {
                if (!Enum.IsDefined<HandshakeType>(handshakeType))
                {
                    Throw("Invalid handshake type value (value is not defined in specification), value received: {0}",
                        BinConverter.ToStringHex((byte)handshakeType));
                }
            }

            public void ExpectedOrderOfHandshakeType(HandshakeType receivedType, HandshakeType expectedType)
            {
                if (receivedType != expectedType)
                {
                    Throw("Expected other handshake message type than received. Received : {0}, expected: {1}",
                        AlertDescription.UnexpectedMessage,
                        BinConverter.ToStringHex((byte)receivedType),
                        BinConverter.ToStringHex((byte)expectedType));
                }
            }

            public void RecordTypeIsHandshareAndNotInterleavedWithOtherRecordTypes(ContentType recordType)
            {
                if (recordType != ContentType.Handshake)
                {
                    Throw("Handshake record types are not interleaved on record layer. " + 
                        "Expected record content type: {0}, current record content type: {1}",
                        ContentType.Handshake,
                        recordType);
                }
            }

            /* 5.1. Record Layer */
            public void NotZeroLengthFragmentsOfHandshake(int recordLength)
            {
                if (recordLength == 0)
                {
                    Throw("No zero length records of handshake types");
                }
            }

            public void ThrowGeneral(bool condition, string msg)
            {
                if (condition) ThrowGeneral(msg);
            }

            public void ThrowGeneral(string msg)
            {
                Throw(msg);
            }

            private void Throw(string msg, AlertDescription? alert, params object[] args)
            {
                msg = string.Format(msg, args);
                msg = string.Format("Handshake: {0}", msg);

                throw new Tls13Exception("","", msg);
            }

            private void Throw(string msg, params object[] args)
            {
                Throw(msg, null, args);
            }

            internal void SignatureAlgorithms_SupportedSignatureAlgoritmsLength(ushort supportedSignatureAlgorithmsLength)
            {
                if (supportedSignatureAlgorithmsLength < 2)
                    Throw("Signature algorithms: minimum length 2 ");
                if (supportedSignatureAlgorithmsLength % 2 != 0)
                    Throw("Signature algorithms: length not a multiple of 2");

            }

            internal void KeyShare_KeyShareEntry_KeyExchangeLength(ushort keyExchangeLength)
            {
                if (keyExchangeLength < 1)
                    Throw("key share: key exchange entry length less that 1 (minimum is 1)");
            }

            internal void ClientHello_CipherSuiteLength(int ciphSuiteLen)
            {
                if (ciphSuiteLen < 2)
                    Throw("Cipher suite length less than 2 minimum is 2");
                if (ciphSuiteLen % 2 != 0)
                    Throw("Cipher suite length not a multiple of 2");
            }

            internal void SelectedSuiteAndEcEcdheGroupAndSignAlgo(bool groupOk, bool cipherSuiteOk, bool signAlgoOk)
            {
                AlertFatal(!groupOk, AlertDescription.HandshakeFailure, "client supported groups not overlap in this instance/implementation");
                AlertFatal(!cipherSuiteOk, AlertDescription.HandshakeFailure, "Received cipher suites doesn't overlap with supported in this instance/implementation");
                AlertFatal(!signAlgoOk, AlertDescription.HandshakeFailure, "signature algorithm doesn't overlap with supported in this instance/implementation");
            }
        }

        public class ExtensionsValidate : ValidateBase
        {
            public ExtensionsValidate(ValidationErrorHandler handler, string containerMessage = null) : base(handler, "Extensions " + (containerMessage ?? string.Empty))
            {
            }

            public void GeneralValidateClientHelloExtensions(ClientHello clientHello)
            {
                HashSet<ExtensionType> extensionsHashSet = new HashSet<ExtensionType>(clientHello.Extensions.Select(e => e.ExtensionType).ToArray());
                var extensions = clientHello.Extensions;

                SharedExtensionsValidate(clientHello.Extensions, HandshakeType.ClientHello);

                if (extensionsHashSet.Contains(ExtensionType.PreSharedKey) &&
                    clientHello.Extensions[clientHello.Extensions.Count - 1].ExtensionType != ExtensionType.PreSharedKey)
                {
                    AlertFatal(true, AlertDescription.Illegal_parameter, "Extensions: containst extension 'presharedkey' but this extension is not last in the list (must be last)");
                }

                AlertFatal(!extensionsHashSet.Contains(ExtensionType.SupportedVersions), AlertDescription.MissingExtension, "Missing extension: SupportedVersions");
                AlertFatal(extensionsHashSet.Contains(ExtensionType.PreSharedKey) && !extensionsHashSet.Contains(ExtensionType.PskKeyExchangeModes),
                    AlertDescription.MissingExtension,
                    "PskKeyExchangeModes extension is required if PreSharedKey extension is present on the list");

                ushort[] supportedVersions = clientHello.GetExtension<ClientSupportedVersionsExtension>(ExtensionType.SupportedVersions).Versions;
                bool tls13NotFound = true;

                for (int i = 0; tls13NotFound && i < supportedVersions.Length; i++)
                {
                    tls13NotFound = supportedVersions[i] != 0x0304;
                }

                AlertFatal(tls13NotFound, AlertDescription.ProtocolVersion, "TLS 1.3 version was not found int version extension and implementation supports only 1.3");

                // validate alpn
                if (clientHello.TryGetExtension<ProtocolNameListExtension>(ExtensionType.ApplicationLayerProtocolNegotiation, out var alpnExtension))
                {
                    var protocolNamesList = alpnExtension.ProtocolNamesList;

                    foreach (var nameBytes in protocolNamesList)
                    {
                        // no empty strings
                        if (nameBytes.Length == 0) AlertFatal(AlertDescription.Illegal_parameter, "zero length of protocol name in alpn extension");
                        if (nameBytes[0] == 0) AlertFatal(AlertDescription.Illegal_parameter, "zero byte as first byte in alpn protocol name in list");
                    }
                }
            }

            public void GeneralValidateServerHelloExtensions(ServerHello hello)
            {
                SharedExtensionsValidate(hello.Extensions, HandshakeType.ServerHello);
            }

            public void SharedExtensionsValidate(List<Extension> extensions, HandshakeType handshakeType)
            {
                // 1. must be called for all messages where extensions list appear, this method must be safe
                // this stores shared validation for extensions that appear in one or more messages
                // doesnt make sens copy & paste because same validatation in multiple places
                //
                // This method must not perform context-specific validation
                // (e.validate serverhello extension in context of what was sent in clienthello message)

                HashSet<ExtensionType> extensionsHashSet = new HashSet<ExtensionType>();

                foreach (var ext in extensions)
                {
                    if (extensionsHashSet.Contains(ext.ExtensionType))
                    {
                        AlertFatal(true, AlertDescription.Illegal_parameter, "Extensions: more that one extension of given type exists. Cannot be duplicate extensions");
                    }

                    extensionsHashSet.Add(ext.ExtensionType);

                    AlertFatal(IllegalExtensionAppearInMessage(ext.ExtensionType, handshakeType), AlertDescription.Illegal_parameter, "Not expected extension");
                }

                var recordSizeLimitExt = extensions.FirstOrDefault(e => e.ExtensionType == ExtensionType.RecordSizeLimit) as RecordSizeLimitExtension;
                if (recordSizeLimitExt != null)
                {
                    if (recordSizeLimitExt.RecordSizeLimit < Tls13Const.Extension_RecordSizeLimit_RecordSizeLimit_MinValue ||
                        recordSizeLimitExt.RecordSizeLimit > Tls13Const.Extension_RecordSizeLimit_RecordSizeLimit_MaxValue)
                    {
                        AlertFatal_IllegalParameter("recordsizelimitextension.recordsizelimit not in range allowed");
                    }
                }
            }

            public void ThrowGeneral(bool condition, string msg)
            {
                if (condition) ThrowGeneralException(msg);
            }

            public void ThrowGeneralException(string msg)
            {
                Throw(msg);
            }

            static void Throw(string msg)
            {
                msg = String.Format("Extensions: {0}", msg);
                throw new Tls13Exception("", "", msg);
            } 

            internal void ServerNameList_ServerNameListLength(ushort serverNameListLength)
            {
                if (serverNameListLength < 1)
                {
                    Throw("Minimum server name list length is 1");
                }
            }

            internal void ServerNameList_NameTypeEnum(ServerNameListExtension.NameTypeEnum nameType)
            {
                if (!Enum.IsDefined<ServerNameListExtension.NameTypeEnum>(nameType))
                {
                    Throw("server name list name type not defined");
                }
            }

            internal void ServerNameList_HostNameLength(ushort hostNameLength)
            {
                if (hostNameLength < 1)
                    Throw("server name list - minimum host length 1 but current 0");
            }

            internal void SupportedGroups_NamedCurveListLength(ushort namedCurveListLength)
            {
                if (namedCurveListLength < 2)
                    Throw("Named curve list: list doesnt contain any named curve (count of bytes less than 2). Expected to have at least 1 curve in the list");
                if (namedCurveListLength % 2 != 0)
                    Throw("named curve list: invalid length of list. Should be multiple of 2");
            }

            internal void ALPN_ProtocolNameListLength(ushort protocolNameListLength)
            {
                if (protocolNameListLength < 2)
                    Throw("ALPN: length less than 2 (minimum 2)");
            }

            internal void ALPN_ProtocolNameLength(ushort protocolNameLength)
            {
                if (protocolNameLength < 1 || protocolNameLength > 255)
                    Throw("alpn: protocol name invalid, minimum 1 max 255");
            }

            internal void ALPN_AlertFatal_NoApplicationProtocol()
            {
                AlertFatal(AlertDescription.NoApplicationProtocol, "ALPN: Server decided do reject handshake because application layer protocol does not match or not supported");
            }

            internal void SupportedVersions_Client_VersionsLength(ushort versionsLength)
            {
                if (versionsLength < 2)
                    Throw("supported versions: minimum length of versions is 2 (in bytes)");
                if (versionsLength % 2 != 0)
                    Throw("supported versions: Invalid length of versions, not a multiple of 2");
            }
        }

        static bool IllegalExtensionAppearInMessage(ExtensionType type, HandshakeType msgWhereExtensionIsPresent)
        {
            HandshakeType[] validMsgTypes;
            bool isValid = true;

            if (ValidExtensionsForHandshakeType.TryGetValue(type, out validMsgTypes))
            {
                isValid = false;
                for (int i = 0; i < validMsgTypes.Length; i++) isValid |= (validMsgTypes[i] == msgWhereExtensionIsPresent);
            }

            return !isValid;
        }

        static Dictionary<ExtensionType, HandshakeType[]> ValidExtensionsForHandshakeType =
            new Dictionary<ExtensionType, HandshakeType[]>
            {
                [ExtensionType.ServerName] = new HandshakeType[]
                {
                    HandshakeType.ClientHello,
                    HandshakeType.EncryptedExtensions
                },
                [ExtensionType.MaxFragmentLength] = new HandshakeType[]
                {
                    HandshakeType.ClientHello,
                    HandshakeType.EncryptedExtensions
                },
                [ExtensionType.StatusRequest] = new HandshakeType[]
                {
                    HandshakeType.ClientHello,
                    HandshakeType.CertificateRequest,
                    HandshakeType.Certificate,
                },
                [ExtensionType.SupportedGroups] = new HandshakeType[]
                {
                    HandshakeType.ClientHello,
                    HandshakeType.EncryptedExtensions,
                },
                [ExtensionType.SignatureAlgorithms] = new HandshakeType[]
                {
                    HandshakeType.ClientHello,
                    HandshakeType.CertificateRequest,
                },
                [ExtensionType.UseSrtp] = new HandshakeType[]
                {
                    HandshakeType.ClientHello,
                    HandshakeType.EncryptedExtensions,
                },
                [ExtensionType.Heartbeat] = new HandshakeType[]
                {
                    HandshakeType.ClientHello,
                    HandshakeType.EncryptedExtensions,
                },
                [ExtensionType.ApplicationLayerProtocolNegotiation] = new HandshakeType[]
                {
                    HandshakeType.ClientHello,
                    HandshakeType.EncryptedExtensions,
                },
                [ExtensionType.SignedCertificateTimestamp] = new HandshakeType[]
                {
                    HandshakeType.ClientHello,
                    HandshakeType.Certificate,
                    HandshakeType.CertificateRequest
                },
                [ExtensionType.ClientCertificateType] = new HandshakeType[]
                {
                    HandshakeType.ClientHello,
                    HandshakeType.EncryptedExtensions,
                },
                [ExtensionType.ServerCertificateType] = new HandshakeType[]
                {
                    HandshakeType.ClientHello,
                    HandshakeType.EncryptedExtensions,
                },
                [ExtensionType.Padding] = new HandshakeType[]
                {
                    HandshakeType.ClientHello,
                },
                [ExtensionType.KeyShare] = new HandshakeType[]
                {
                    HandshakeType.ClientHello,
                    HandshakeType.ServerHello,
                    HandshakeType.HelloRetryRequest_ARCTIUM_INTERNAL_TEMPORARY,
                },
                [ExtensionType.PreSharedKey] = new HandshakeType[]
                {
                    HandshakeType.ClientHello,
                    HandshakeType.ServerHello,
                },
                [ExtensionType.PskKeyExchangeModes] = new HandshakeType[]
                {
                    HandshakeType.ClientHello,
                },
                [ExtensionType.EarlyData] = new HandshakeType[]
                {
                    HandshakeType.ClientHello,
                    HandshakeType.EncryptedExtensions,
                    HandshakeType.NewSessionTicket,
                },
                [ExtensionType.Cookie] = new HandshakeType[]
                {
                    HandshakeType.ClientHello,
                    HandshakeType.HelloRetryRequest_ARCTIUM_INTERNAL_TEMPORARY,
                },
                [ExtensionType.SupportedVersions] = new HandshakeType[]
                {
                    HandshakeType.ClientHello,
                    HandshakeType.ServerHello,
                    HandshakeType.HelloRetryRequest_ARCTIUM_INTERNAL_TEMPORARY,
                },
                [ExtensionType.CertificateAuthorities] = new HandshakeType[]
                {
                    HandshakeType.ClientHello,
                    HandshakeType.Certificate,
                },
                [ExtensionType.OidFilters] = new HandshakeType[]
                {
                    HandshakeType.Certificate,
                },
                [ExtensionType.PostHandshakeAuth] = new HandshakeType[]
                {
                    HandshakeType.ClientHello,
                },
                [ExtensionType.SignatureAlgorithmsCert] = new HandshakeType[]
                {
                    HandshakeType.ClientHello,
                    HandshakeType.Certificate
                },
            };
    }
}
