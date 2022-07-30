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
using Arctium.Shared.Helpers.Binary;
using System;

namespace Arctium.Connection.Tls.Tls13.Protocol
{
    static class Validate
    {
        public static class RecordLayer
        {
            const ushort LegacyRecordVersion = 0x0303;
            const ushort LegacyRecordVersion0301 = 0x0301;
            const ushort MaxRecordLength = 2 << 14;

            public static void ValidateContentType(byte contentType)
            {
                if (contentType != (byte)ContentType.Alert &&
                    contentType != (byte)ContentType.ApplicationData &&
                    contentType != (byte)ContentType.ChangeCipherSpec &&
                    contentType != (byte)ContentType.Handshake)
                {
                    Throw(string.Format("Received record with unrecognized content type value. Received content Type value: {0}", contentType));
                }
            }

            public static void ProtocolVersion(ushort protocolVersion, bool isInitialClientHello)
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

            public static void Length(ushort length)
            {
                if (length > MaxRecordLength)
                    Throw("Received record with length exceeded maximum length. Max length: {0}, received length: {1}", MaxRecordLength, length);
            }

            private static void Throw(string msg, params object[] args)
            {
                throw new Tls13Exception(string.Format("Record Layer: {0}", string.Format(msg, args)));
            }
        }

        public static class Handshake
        {
            public static void ValidHandshakeType(HandshakeType handshakeType)
            {
                if (!Enum.IsDefined<HandshakeType>(handshakeType))
                {
                    Throw("Invalid handshake type value (value is not defined in specification), value received: {0}",
                        BinConverter.ToStringHex((byte)handshakeType));
                }
            }

            public static void ExpectedOrderOfHandshakeType(HandshakeType receivedType, HandshakeType expectedType)
            {
                if (receivedType != expectedType)
                {
                    Throw("Expected other handshake message type than received. Received : {0}, expected: {1}",
                        AlertDescription.UnexpectedMessage,
                        BinConverter.ToStringHex((byte)receivedType),
                        BinConverter.ToStringHex((byte)expectedType));
                }
            }   

            public static void RecordTypeIsHandshareAndNotInterleavedWithOtherRecordTypes(ContentType recordType)
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
            public static void NotZeroLengthFragmentsOfHandshake(int recordLength)
            {
                if (recordLength == 0)
                {
                    Throw("No zero length records of handshake types");
                }
            }

            private static void Throw(string msg, AlertDescription? alert, params object[] args)
            {
                msg = string.Format(msg, args);
                msg = string.Format("Handshake: {0}", msg);

                throw new Tls13Exception(msg, alert);
            }

            private static void Throw(string msg, params object[] args)
            {
                Throw(msg, null, args);
            }
        }
    }
}
