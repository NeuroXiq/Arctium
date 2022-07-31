/* FOLLOWING SPECIFICATION IMPLEMENTED: 
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

using Arctium.Connection.Tls.Tls13.API;
using Arctium.Connection.Tls.Tls13.Model;
using Arctium.Connection.Tls.Tls13.Model.Extensions;
using Arctium.Shared.Helpers.Binary;
using System;

namespace Arctium.Connection.Tls.Tls13.Protocol
{
    class Validate
    {
        public RecordLayerValidate RecordLayer { get; private set; }
        public HandshakeValidate Handshake { get; private set; }
        public ExtensionsValidate Extensions { get; private set; }

        public Validate()
        {
            this.RecordLayer = new RecordLayerValidate();
            this.Handshake = new HandshakeValidate();
            this.Extensions = new ExtensionsValidate();
        }

        public class RecordLayerValidate
        {
            const ushort LegacyRecordVersion = 0x0303;
            const ushort LegacyRecordVersion0301 = 0x0301;
            const ushort MaxRecordLength = 2 << 14;

            public void ValidateContentType(byte contentType)
            {
                if (contentType != (byte)ContentType.Alert &&
                    contentType != (byte)ContentType.ApplicationData &&
                    contentType != (byte)ContentType.ChangeCipherSpec &&
                    contentType != (byte)ContentType.Handshake)
                {
                    Throw(string.Format("Received record with unrecognized content type value. Received content Type value: {0}", contentType));
                }
            }

            public void ProtocolVersion(ushort protocolVersion, bool isInitialClientHello)
            {
                if (protocolVersion == LegacyRecordVersion ||
                    (isInitialClientHello && LegacyRecordVersion0301 == protocolVersion))
                {
                    return;
                }

                Throw("Received record with invalid LegacyRecordVersion. Expected: {0} but current: {1}",
                    BinConverter.ToStringHex(LegacyRecordVersion),
                    BinConverter.ToStringHex(protocolVersion));

            }

            public void Length(ushort length)
            {
                if (length > MaxRecordLength)
                    Throw("Received record with length exceeded maximum length. Max length: {0}, received length: {1}", MaxRecordLength, length);
            }

            private void Throw(string msg, params object[] args)
            {
                throw new Tls13Exception(string.Format("Record Layer: {0}", string.Format(msg, args)));
            }
        }

        public class HandshakeValidate
        {
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
                        "Expected record content type: {0}, current record content type: {1]",
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

            public void ThrowGeneral(string msg)
            {
                Throw(msg);
            }

            private void Throw(string msg, AlertDescription? alert, params object[] args)
            {
                msg = string.Format(msg, args);
                msg = string.Format("Handshake: {0}", msg);

                throw new Tls13Exception(msg, alert);
            }

            private void Throw(string msg, params object[] args)
            {
                Throw(msg, null, args);
            }
        }

        public class ExtensionsValidate
        {
            public void ThrowGeneralException(string msg)
            {
                Throw(msg);
            }

            static void Throw(string msg)
            {
                msg = String.Format("Extensions: {0}", msg);
                throw new Tls13Exception(msg);
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
        }
    }
}
