// using Arctium.Standards.Connection.Tls.Tls13.API;
using Arctium.Standards.Connection.Tls.Tls13.Model;
using Arctium.Standards.Connection.Tls.Tls13.Model.Extensions;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Buffers;
using System;
using System.Collections.Generic;
using static Arctium.Standards.Connection.Tls.Tls13.Model.Extensions.SupportedGroupExtension;

namespace Arctium.Standards.Connection.Tls.Tls13.Protocol
{
    class ModelDeserialization
    {
        private Validate validate;
        private Endpoint currentEndpoint;
        private Dictionary<ExtensionType, Func<byte[], int, Extension>> extensionsDeserialize;
        private Dictionary<ExtensionType, Func<byte[], int, Extension>> extensionsDeserializeOnClientSide;
        private Dictionary<ExtensionType, Func<byte[], int, Extension>> extensionsDeserializeOnServerSide;
        private Dictionary<Type, Func<byte[], int, object>> messageDeserialize;

        public ModelDeserialization(Validate validate)
        {
            this.validate = validate;
            this.currentEndpoint = currentEndpoint;

            extensionsDeserialize = new Dictionary<ExtensionType, Func<byte[], int, Extension>>()
            {
                [ExtensionType.ApplicationLayerProtocolNegotiation] = DeserializeExtension_ALPN,
                [ExtensionType.Cookie] = DeserializeExtension_Cookie,
                [ExtensionType.SignatureAlgorithms] = DeserializeExtension_SignatureAlgorithms,
                [ExtensionType.SignatureAlgorithmsCert] = DeserializeExtension_SignatureAlgorithmsCert,
                [ExtensionType.SupportedGroups] = DeserializeExtension_SupportedGroups,
                [ExtensionType.PreSharedKey] = DeserializeExtension_PreSharedKey_Client,
                [ExtensionType.ServerName] = DeserializeExtension_ServerName,
            };

            extensionsDeserializeOnClientSide = new Dictionary<ExtensionType, Func<byte[], int, Extension>>()
            {
                [ExtensionType.SupportedVersions] = DeserializeExtension_SupportedVersions_Client,
                [ExtensionType.KeyShare] = DeserializeExtension_KeyShare_Client,
            };

            extensionsDeserializeOnServerSide = new Dictionary<ExtensionType, Func<byte[], int, Extension>>()
            {
                [ExtensionType.SupportedVersions] = DeserializeExtension_SupportedVersions_Server,
                [ExtensionType.KeyShare] = DeserializeExtension_KeyShare_Server,
                [ExtensionType.PreSharedKey] = DeserializeExtension_PreSharedKey_Server,
                [ExtensionType.PskKeyExchangeModes] = DeserializeExtension_PskKeyExchangeModes_Server
            };

            messageDeserialize = new Dictionary<Type, Func<byte[], int, object>>()
            {
                [typeof(ServerHello)] = DeserializeServerHello,
                [typeof(ClientHello)] = DeserializeClientHello,
                [typeof(EncryptedExtensions)] = DeserializeEncryptedExtensions,
                [typeof(CertificateVerify)] = DeserializeCertificateVerify,
                [typeof(Finished)] = DeserializeFinished,
                [typeof(Certificate)] = DeserializeCertificate,
                [typeof(NewSessionTicket)] = DeserializeNewSessionTicket
            };
        }

        private object DeserializeNewSessionTicket(byte[] buf, int offs)
        {
            HandshakeType type = (HandshakeType)buf[offs];
            int msgLen = ToInt3BytesBE(buf, offs + 1);
            RangeCursor c;

            uint ticketLifetime, ticketAgeAdd;
            int ticketLen, extLen;
            byte[] ticket, ticketNonce;
            List<Extension> extensions = new List<Extension>();

            validate.NewSessionTicket.AlertFatalDecodeError(msgLen < 6, "handshake.length", "invalid length (minimum length is 6 bytes)");

            c = new RangeCursor(offs + 4, offs + 4 + msgLen - 1);

            validate.Handshake.AlertFatal(type != HandshakeType.NewSessionTicket, AlertDescription.UnexpectedMessage, "expected to deserialize newessionticket");

            c.ThrowIfOutside(3);
            ticketLifetime = MemMap.ToUInt4BytesBE(buf, c);
            
            c += 4; c.ThrowIfOutside(3);
            ticketAgeAdd = MemMap.ToUInt4BytesBE(buf, c);

            c += 4;
            int ticketNonceLen = buf[c];
            ticketNonce = new byte[ticketNonceLen];
            
            MemCpy.Copy(buf, c + 1, ticketNonce, 0, ticketNonceLen);
            c += 1 + ticketNonceLen;

            ticketLen = MemMap.ToUShort2BytesBE(buf, c);
            validate.NewSessionTicket.AlertFatalDecodeError(ticketLen < 1, "ticket.length", "length less than 1");
            
            c += 2;

            ticket = new byte[ticketLen];
            MemCpy.Copy(buf, c, ticket, 0, ticketLen);

            c += ticketLen;
            c.ThrowIfOutside(1);

            extLen = MemMap.ToUShort2BytesBE(buf, c);
            c++;

            while(!c.OnMaxPosition)
            {
                c++;
                var result = DeserializeExtension(Endpoint.Client, buf, c);
                c += result.Length - 1;
            }

            validate.NewSessionTicket.AlertFatalDecodeError(!c.OnMaxPosition, "handshake.length", "cursor not on last position");

            return new NewSessionTicket(ticketLifetime, ticketAgeAdd, ticketNonce, ticket, extensions.ToArray());
        }

        private Extension DeserializeExtension_PreSharedKey_Client(byte[] buf, int offs)
        {
            RangeCursor cursor;
            int len;
            ExtensionDeserializeSetup(buf, offs, out cursor, out len);

            validate.Extensions.AlertFatalDecodeError(len != 2, "fromserver.presharedkey.selectedidentity", "length should be equal 2 (single selected identity by server");

            ushort selectedIdentity = MemMap.ToUShort2BytesBE(buf, cursor);

            return new PreSharedKeyServerHelloExtension(selectedIdentity);
        }

        public static int HelperGetOffsetOfPskExtensionInClientHello(byte[] buffer, int clientHelloOffset)
        {
            int msgLen = ToInt3BytesBE(buffer, clientHelloOffset + 1);
            int endOffs = clientHelloOffset + msgLen +4;

            int o = clientHelloOffset + 4;
            // random + protocol ver
            o += 32 + 2;

            // leg sess id
            o += buffer[o] + 1;

            int suitesLen = MemMap.ToUShort2BytesBE(buffer, o);
            o += suitesLen + 2;

            // comp meths
            o += 1 + buffer[o];

            // points to extensions len vector
            // move to first extension
            o += 2;

            while (o < endOffs)
            {
                ExtensionType type = (ExtensionType)MemMap.ToUShort2BytesBE(buffer, o);
                int extLen = MemMap.ToUShort2BytesBE(buffer, o + 2);

                if (type == ExtensionType.PreSharedKey)
                {
                    // points to offeredpsks.identities (to 2-byte length vector)
                    o += 4;

                    int identitiesLen = MemMap.ToUShort2BytesBE(buffer, o);

                    o += identitiesLen + 2;

                    return o;
                }

                o += 4 + extLen;
            }

            return -1;
        }

        private Extension DeserializeExtension_PskKeyExchangeModes_Server(byte[] buf, int offs)
        {
            int length;
            RangeCursor cursor;
            ExtensionDeserializeSetup(buf, offs, out cursor, out length);

            validate.Extensions.AlertFatalDecodeError(length < 2, "PskKeyExchangeModes", "extension length < 2");

            int keModesLen = buf[cursor];
            List<PreSharedKeyExchangeModeExtension.PskKeyExchangeMode> modes = new List<PreSharedKeyExchangeModeExtension.PskKeyExchangeMode>();

            validate.Extensions.AlertFatalDecodeError(keModesLen < Tls13Const.PskKeyExchangeModes_KeModesMinVectorLength, "PskKeyExchangeModes.ke_modes vector len", "minimum is 1");

            for (int i = 0; i < keModesLen; i++)
            {
                cursor++;
                modes.Add((PreSharedKeyExchangeModeExtension.PskKeyExchangeMode)buf[cursor]);
            }

            validate.Extensions.AlertFatalDecodeError(!cursor.OnMaxPosition, "PskKeyExchangeModes.extension_length vector length", "cursor not on max position");

            return new PreSharedKeyExchangeModeExtension(modes.ToArray());
        }

        private Extension DeserializeExtension_KeyShare_Client(byte[] buf, int offs)
        {
            // following possible:
            // 1. group + keybytes
            // 2. group + null (no key bytes, when server sends helloretryrequest)
            // 3. null + null (no keyShareEntry, possible when 'PskKeyExchangeMode.psk_ke' pre shared key without DH/DHE)
            int length;
            RangeCursor cursor;
            ExtensionDeserializeSetup(buf, offs, out cursor, out length);

            validate.Extensions.AlertFatalDecodeError(length < 2, "extension.length", "keyshare extension length less than 2 bytes");

            SupportedGroupExtension.NamedGroup group;
            ushort keyExchLen;
            byte[] keyExch;

            group = (SupportedGroupExtension.NamedGroup)((buf[cursor + 0] << 8) | (buf[cursor + 1] << 0));

            if (length == 0)
            {
                return new KeyShareServerHelloExtension(null);
            }
            if (length == 2)
            {
                return new KeyShareHelloRetryRequestExtension((NamedGroup)group);
            }

            cursor += 2;

            cursor.ThrowIfShiftOutside(1);

            keyExchLen = MemMap.ToUShort2BytesBE(buf, cursor);
            keyExch = new byte[keyExchLen];

            if (keyExchLen > 0)
            {
                cursor += 2;

                MemCpy.Copy(buf, cursor, keyExch, 0, keyExchLen);

                cursor += keyExchLen - 1;
            }

            validate.Extensions.AlertFatalDecodeError(!cursor.OnMaxPosition, "probably one or more vectors length",
                "keyshare client side: cursor is not on last position after deserialize)");

            KeyShareServerHelloExtension ext = new KeyShareServerHelloExtension(new KeyShareEntry(group, keyExch));

            return ext;
        }


        private object DeserializeClientHello(byte[] buffer, int offs)
        {
            RangeCursor cursor = new RangeCursor(offs, 4);
            validate.Handshake.ThrowGeneral(buffer[cursor] != (byte)HandshakeType.ClientHello, "not client hello");
            int msgLen = ToInt3BytesBE(buffer, cursor + 1);
            cursor.ChangeMaxPosition(msgLen + offs + 4 - 1);
            cursor += 4;


            int startOffset = offs + 4;

            int versionOffs = 4;
            int randomOffs = versionOffs + 2;
            int legSessIdOffs = randomOffs + 32;
            int ciphSuitOffs = -1;
            int legCompMethOffs = -1;
            int extOffs = -1;
            int legacySessIdLen = -1;
            int ciphSuiteLen = -1;
            int legComprLen = -1;
            int extLen = -1;

            byte[] random = new byte[32];
            byte[] legacySessId = null;
            byte[] legComprMeth = null;

            int minMsgLen = 2 + 32 + 1 + 2 + 1 + 2;
            

            

            //AppendMinimum(minMsgLen, true);

            ClientHello msg = new ClientHello();

            ushort protocolVerson = MemMap.ToUShort2BytesBE(buffer, cursor);
            cursor += 2;
            MemCpy.Copy(buffer, cursor, random, 0, 32);
            cursor += 32;
            legacySessIdLen = (int)buffer[cursor];
            legacySessId = new byte[legacySessIdLen];
            cursor += 1;

            cursor.ThrowIfOutside(legacySessIdLen - 1);
            MemCpy.Copy(buffer, cursor, legacySessId, 0, legacySessIdLen);
            cursor += legacySessIdLen;

            //LoadToLength(ciphSuitOffs + 1 + 2);
            cursor.ThrowIfOutside( 1);
            ciphSuiteLen = MemMap.ToUShort2BytesBE(buffer, cursor);
            validate.Handshake.ClientHello_CipherSuiteLength(ciphSuiteLen);
            // cipherSuites = new byte[ciphSuiteLen];

            cursor += 2;
            cursor.ThrowIfOutside(ciphSuiteLen - 1);

            //MemCpy.Copy(buffer, cursor, cipherSuites, 0, ciphSuiteLen);

            CipherSuite[] cipherSuites = new CipherSuite[ciphSuiteLen / 2];
            for (int i = 0; i < ciphSuiteLen; i += 2) cipherSuites[i / 2] = (CipherSuite)MemMap.ToUShort2BytesBE(buffer, cursor + i);

            cursor += ciphSuiteLen;

            //LoadToLength((legCompMethOffs + 1) + 1);
            cursor.ThrowIfOutside(1);
            legComprLen = buffer[cursor];
            cursor += 1;
            legComprMeth = new byte[legComprLen];
            cursor.ThrowIfOutside(legComprLen - 1);
            MemCpy.Copy(buffer, cursor, legComprMeth, 0, legComprLen);
            cursor += legComprLen;

            // Extensions
            //LoadToLength((legCompMethOffs + legComprLen + 1) + 2);
            extLen = MemMap.ToUShort2BytesBE(buffer, cursor);
            cursor++;

            // Extension[] extensions = DeserializeExtensions(buffer, cursor - 2);

            List<Extension> extensions = new List<Extension>();

            validate.Handshake.ThrowGeneral(extLen > 0 && cursor.CurrentPosition + extLen != cursor.MaxPosition, "invalid extensios length, cursor not on last position");

            while (!cursor.OnMaxPosition)
            {
                cursor++;

                var result = DeserializeExtension(Endpoint.Server, buffer, cursor);

                extensions.Add(result.Extension);

                cursor += result.Length - 1;
            }

            //LoadToLength(extOffs + 1 + 2 + extLen);

            msg.ProtocolVersion = protocolVerson;
            msg.Random = random;
            msg.LegacySessionId = legacySessId;
            msg.CipherSuites = cipherSuites;
            msg.LegacyCompressionMethods = legComprMeth;
            msg.Extensions = extensions;

            // validate.Handshake.ClientHello_ClientHello(msg);

            validate.ClientHello.AlertFatalDecodeError(!cursor.OnMaxPosition, "length" ,"after decoding length doesn't match");

            return msg;
        }

        private Extension DeserializeExtension_PreSharedKey_Server(byte[] buffer, int offset)
        {
            int length;
            RangeCursor cursor, identityCursor, binderEntryCursor;
            ExtensionDeserializeSetup(buffer, offset, out cursor, out length);

            int identitiesLen;
            int bindersLen;
            List<PreSharedKeyClientHelloExtension.PskIdentity> identities = new List<PreSharedKeyClientHelloExtension.PskIdentity>();
            List<byte[]> binders = new List<byte[]>();

            cursor.ThrowIfShiftOutside(1);
            identitiesLen = MemMap.ToUShort2BytesBE(buffer, cursor);
            identityCursor = new RangeCursor(cursor + 1, cursor + 1 + identitiesLen);
            cursor += (identitiesLen + 2);

            cursor.ThrowIfShiftOutside(1);
            bindersLen = MemMap.ToUShort2BytesBE(buffer, cursor);
            binderEntryCursor = new RangeCursor(cursor + 1, cursor + 1 + bindersLen); 
            cursor += (bindersLen + 2) - 1;

            validate.Extensions.AlertFatalDecodeError(!cursor.OnMaxPosition, "extension_length", "invalid extension length");
            validate.Extensions.AlertFatalDecodeError(identitiesLen < Tls13Const.PreSharedKeyExtension_IdentitiesMinLength, "identities vector length", "less than min");
            validate.Extensions.AlertFatalDecodeError(bindersLen < Tls13Const.PreSharedKeyExtension_BindersMinLength, "binders vector length", "less than min");

            while (!identityCursor.OnMaxPosition)
            {
                identityCursor++;
                identityCursor.ThrowIfShiftOutside(1);

                int identityLen = MemMap.ToUShort2BytesBE(buffer, identityCursor);
                identityCursor += 2;

                byte[] identity = new byte[identityLen];
                uint obfuscatedTicketAge;

                validate.Extensions.AlertFatalDecodeError(identityLen < Tls13Const.PreSharedKeyExtension_IdentityMinLength, "identity_length", "minimum length 1");

                identityCursor.ThrowIfShiftOutside(identityLen - 1);
                MemCpy.Copy(buffer, identityCursor, identity, 0, identityLen);

                identityCursor += identityLen;
                identityCursor.ThrowIfShiftOutside(3);
                obfuscatedTicketAge = MemMap.ToUInt4BytesBE(buffer, identityCursor);

                identityCursor += 3;

                identities.Add(new PreSharedKeyClientHelloExtension.PskIdentity(identity, obfuscatedTicketAge));
            }

            while (!binderEntryCursor.OnMaxPosition)
            {
                binderEntryCursor++;
                int binderLen = buffer[binderEntryCursor];
                byte[] binderEntry = new byte[binderLen];

                validate.Extensions.AlertFatalDecodeError(binderLen < Tls13Const.PreSharedKeyExtension_PskBinderEntryMinLength, "binder entry vector len", "less than min");
                binderEntryCursor++;

                MemCpy.Copy(buffer, binderEntryCursor, binderEntry, 0, binderLen);
                binders.Add(binderEntry);

                binderEntryCursor += binderLen - 1;
            }

            return new PreSharedKeyClientHelloExtension(identities.ToArray(), binders.ToArray());
        }

        private Extension DeserializeExtension_SupportedVersions_Client(byte[] buf, int offs)
        {
            int length;
            RangeCursor cursor;
            ExtensionDeserializeSetup(buf, offs, out cursor, out length);

            //if (length != 2) validate.Extensions.ThrowGeneralException("invalid length of suported versions extensions received from server. len should be 2");

            ushort selectedVersion = (ushort)((buf[cursor + 0] << 8) | (buf[cursor + 1]));

            return new ServerSupportedVersionsExtension(selectedVersion);
        }

        private object DeserializeFinished(byte[] buf, int offs)
        {
            RangeCursor cursor = new RangeCursor(offs, 4);
            validate.Handshake.ThrowGeneral(buf[cursor] != (byte)(HandshakeType.Finished), "invalid type: expected finished");

            int len = ToInt3BytesBE(buf, cursor + 1);

            cursor.ChangeMaxPosition(offs + len - 1);
            cursor += 4;

            byte[] verifyData = new byte[len];
            MemCpy.Copy(buf, cursor, verifyData, 0, len);

            return new Finished(verifyData);
        }

        private object DeserializeCertificateVerify(byte[] buf, int offs)
        {
            RangeCursor cursor = new RangeCursor(offs, 4);
            validate.Handshake.ThrowGeneral(buf[cursor] != (byte)(HandshakeType.CertificateVerify), "invalid type expected certificateverify");
            int msgLen = ToInt3BytesBE(buf, cursor + 1);
            
            SignatureSchemeListExtension.SignatureScheme scheme;
            int signatureLen;
            byte[] signature = new byte[0];

            cursor.ChangeMaxPosition(offs + msgLen + 4 - 1);
            cursor += 4;

            cursor.ThrowIfShiftOutside(1);
            scheme = (SignatureSchemeListExtension.SignatureScheme)MemMap.ToUShort2BytesBE(buf, cursor);
            cursor += 2;

            cursor.ThrowIfShiftOutside(1);
            signatureLen = MemMap.ToUShort2BytesBE(buf, cursor);
            cursor++;

            if (signatureLen > 0)
            {
                cursor.ThrowIfShiftOutside(signatureLen);
                cursor++;
                signature = MemCpy.CopyToNewArray(buf, cursor, signatureLen);

                cursor += signatureLen - 1;
            }

            validate.Handshake.ThrowGeneral(!cursor.OnMaxPosition, "cursor not on max position");

            return new CertificateVerify(scheme, signature);
        }

        public Certificate DeserializeCertificate(byte[] buf, int offs /*, CertificateType expectedType*/)
        {
            validate.Handshake.ThrowGeneral(buf[offs + 0] != (byte)HandshakeType.Certificate, "cannot deserialize not a certificate type");
            
            int msgLen = ToInt3BytesBE(buf, offs + 1);
            RangeCursor cursor = new RangeCursor(offs, offs + msgLen + 4 - 1);
            cursor += 4;
            int certListLen;
            List<CertificateEntry> certificateList = new List<CertificateEntry>();
            int requestContextLen;
            byte[] certificateRequestContext;

            requestContextLen = buf[cursor];
            
            if (requestContextLen > 0) cursor.ThrowIfShiftOutside(requestContextLen - 1);
            
            cursor++;

            certificateRequestContext = MemCpy.CopyToNewArray(buf, cursor, requestContextLen);
            cursor += requestContextLen;

            cursor.ThrowIfShiftOutside(2);
            certListLen = ToInt3BytesBE(buf, cursor);
            cursor += 2;

            validate.Handshake.ThrowGeneral(cursor + certListLen != cursor.MaxPosition, "certificate: certListLen invalid");

            while (!cursor.OnMaxPosition)
            {
                byte[] certData;
                int certDataLen, extensionsLength;
                List<Extension> extensions = new List<Extension>();

                cursor++;
                cursor.ThrowIfShiftOutside(2);
                certDataLen = ToInt3BytesBE(buf, cursor);
                cursor += 3;

                validate.Certificate.CertificateEntry_CertificateTypeMinLen(certDataLen);

                cursor.ThrowIfShiftOutside(certDataLen - 1);
                certData = MemCpy.CopyToNewArray(buf, cursor, certDataLen);
                cursor += certDataLen;
                cursor.ThrowIfShiftOutside(1);

                extensionsLength = (buf[cursor] << 8) | buf[cursor + 1];
                cursor++;
                int endExtensions = extensionsLength == 0 ? cursor : cursor + extensionsLength;

                while(cursor != endExtensions)
                {
                    cursor++;

                    var result = DeserializeExtension(Endpoint.Client, buf, cursor);

                    extensions.Add(result.Extension);

                    // points to last extension byte
                    cursor += result.Length - 1;
                }

                certificateList.Add(new CertificateEntry(null, certData, extensions.ToArray()));
            }

            validate.Certificate.Throw(!cursor.OnMaxPosition, "not on max position");

            return new Certificate(certificateRequestContext, certificateList.ToArray());
        }

        private object DeserializeEncryptedExtensions(byte[] buf, int offset)
        {
            validate.Handshake.ThrowGeneral(buf[0 + offset] != (byte)(HandshakeType.EncryptedExtensions), "encrypted extensions: other handshaketype than expected");
            int length = ToInt3BytesBE(buf, offset + 1);

            RangeCursor cursor = new RangeCursor(offset, 4 + length - 1);
            
            // skip handshaketype, length
            cursor += 4;

            int extLen = MemMap.ToUShort2BytesBE(buf, cursor);
            List<Extension> extensions = new List<Extension>();

            validate.Handshake.ThrowGeneral(extLen + cursor + 2 != cursor.MaxPosition + 1,
                "encryptedextensions: extensions length not valid (cursor not on last position)");

            // points to one byte before first extension (second byte of extensions lenght vector ushort)
            cursor++;

            while (!cursor.OnMaxPosition)
            {
                cursor++;

                var result = DeserializeExtension(Endpoint.Client, buf, cursor);

                extensions.Add(result.Extension);

                cursor += result.Length - 1;
            }

            validate.Handshake.ThrowGeneral(!cursor.OnMaxPosition, "encryptedexensions: after deserializing cursor not on last position");

            EncryptedExtensions msg = new EncryptedExtensions(extensions.ToArray());

            return msg;
        }

        private object DeserializeServerHello(byte[] buffer, int offset)
        {
            if (buffer[offset + 0] != (byte)(HandshakeType.ServerHello)) validate.Handshake.ThrowGeneral("invalid type, expected serverhello");

            int length = (buffer[offset + 1] << 16) | (buffer[offset + 2] << 8) | (buffer[offset + 3] << 0);
            int handshakeTypeAndLengthBytesCount = 4;

            RangeCursor cursor = new RangeCursor(offset, offset + handshakeTypeAndLengthBytesCount + length - 1);

            // skip handshaketype, length
            cursor += 4;

            ushort protVersion = (ushort)((buffer[cursor] << 8) | (buffer[cursor + 1]));

            cursor += 2;

            byte[] random = new byte[32];
            byte[] legacySessionIdEcho;

            for (int i = 0; i < 32; i++)
            {
                random[i] = buffer[cursor];
                cursor++;
            }

            int sessionIdEchoLen = buffer[cursor];
            cursor++;
            legacySessionIdEcho = new byte[sessionIdEchoLen];

            for (int i = 0; i < sessionIdEchoLen; i++)
            {
                legacySessionIdEcho[i] = buffer[cursor];
                cursor++;
            }

            CipherSuite cipherSuite = (CipherSuite)(ushort)((buffer[cursor] << 8) | (buffer[cursor + 1] << 0));
            cursor += 2;

            // legacy compression method
            validate.Handshake.ThrowGeneral(buffer[cursor] != 0, "legacy compression method must be 0");
            cursor++;

            List<Extension> extensions = new List<Extension>();

            int extLen = (buffer[cursor] << 8) | (buffer[cursor + 1] << 0);

            

            if (extLen + cursor + 2!= cursor.MaxPosition + 1) validate.Handshake.ThrowGeneral("invalid extensions length (not meet end)");

            // before this cursor points to extensions length
            cursor += 1;

            if (extLen > 0)
            {
                while (cursor != cursor.MaxPosition)
                {
                    cursor++;

                    var result = DeserializeExtension(Endpoint.Client, buffer, cursor);

                    extensions.Add(result.Extension);

                    cursor += result.Length - 1;
                }
            }

            validate.Handshake.ThrowGeneral(!cursor.OnMaxPosition, "serverhello: after deserialize cursor not on last position");

            return new ServerHello(random, legacySessionIdEcho, cipherSuite, extensions);
        }

        #region Extensions

        public T Deserialize<T>(byte[] buffer, int offset)
        {
            if (!messageDeserialize.ContainsKey(typeof(T))) throw new Exception("internal: unrecognized object type: " + typeof(T).Name);
            
            return (T)messageDeserialize[typeof(T)](buffer, offset);
        }

        public ExtensionDeserializeResult DeserializeExtension(Endpoint currentEndpoint, byte[] buffer, RangeCursor cursor)
        {
            int maxLength = cursor.MaxPosition - cursor.CurrentPosition + 1;
            if (maxLength < 4)
                validate.Extensions.ThrowGeneralException(string.Format("Invalid extension length, minimum is 4 but current: {0}", maxLength));

            ExtensionType extensionType = (ExtensionType)MemMap.ToUShort2BytesBE(buffer, cursor);
            ushort extensionLength = MemMap.ToUShort2BytesBE(buffer, cursor + 2);
            int totalExtensionLength = extensionLength + 4;

            if (totalExtensionLength > maxLength)
                validate.Extensions.ThrowGeneralException(String.Format("Invalid extension lenght. Extension length exceed maximum length that is expected for that extension"));

            ExtensionDeserializeResult result;
            Extension extension;

            if (currentEndpoint == Endpoint.Client && extensionsDeserializeOnClientSide.ContainsKey(extensionType))
            {
                extension = extensionsDeserializeOnClientSide[extensionType](buffer, cursor);
            }
            else if (currentEndpoint == Endpoint.Server && extensionsDeserializeOnServerSide.ContainsKey(extensionType))
            {
                extension = extensionsDeserializeOnServerSide[extensionType](buffer, cursor);
            }
            else if (!extensionsDeserialize.ContainsKey(extensionType))
            {
                extension = new UnknowExtension(extensionType);
            }
            else
            {
                extension = extensionsDeserialize[extensionType](buffer, cursor);
            }

            result = new ExtensionDeserializeResult
            {
                IsRecognized = true,
                Length = totalExtensionLength,
                Extension = extension
            };

            return result;
        }

        private Extension DeserializeExtension_ServerName(byte[] buffer, int offset)
        {
            ushort contentLength = MemMap.ToUShort2BytesBE(buffer, offset + 2);
            ushort serverNameListLength = 0, hostNameLength = 0;
            int maxCursorPosition = (4 + contentLength + offset) - 1;
            List<ServerNameListExtension.ServerName> serverNameList = new List<ServerNameListExtension.ServerName>();
            RangeCursor cursor = new RangeCursor(offset + 4, maxCursorPosition);

            cursor.ThrowIfShiftOutside(1);
            serverNameListLength = MemMap.ToUShort2BytesBE(buffer, cursor);
            cursor.ThrowIfShiftOutside(serverNameListLength - 1);

            validate.Extensions.ServerNameList_ServerNameListLength(serverNameListLength);

            cursor += 1;

            while (cursor < maxCursorPosition)
            {
                cursor++;

                // [<cursor> 1 byte type][2 bytes len][content of length 'len']

                cursor.ThrowIfShiftOutside(2);
                ServerNameListExtension.NameTypeEnum nameType = (ServerNameListExtension.NameTypeEnum)buffer[cursor];
                hostNameLength = MemMap.ToUShort2BytesBE(buffer, cursor + 1);

                validate.Extensions.ServerNameList_NameTypeEnum(nameType);
                validate.Extensions.ServerNameList_HostNameLength(hostNameLength);

                cursor += 3;
                // [..][..][<cursor>]

                byte[] hostName = new byte[hostNameLength];
                MemCpy.Copy(buffer, cursor, hostName, 0, hostNameLength);
                serverNameList.Add(new ServerNameListExtension.ServerName(nameType, hostName));

                cursor += hostNameLength - 1;
            }

            validate.Extensions.ThrowGeneral(!cursor.OnMaxPosition, "servername_extension: after deserializing cursor not on last");

            return new ServerNameListExtension(serverNameList.ToArray());
        }

        private Extension DeserializeExtension_KeyShare_Server(byte[] buffer, int offset)
        {
            int length;
            RangeCursor cursor;

            ExtensionDeserializeSetup(buffer, offset, out cursor, out length);

            if (length < 2)
                validate.Handshake.ThrowGeneral("key share: content length less than 2");

            ushort clientSharedLength = MemMap.ToUShort2BytesBE(buffer, cursor);
            List<KeyShareEntry> keyShareEntires = new List<KeyShareEntry>();

            if (clientSharedLength > 0)
            {
                cursor++;

                validate.Handshake.ThrowGeneral(clientSharedLength < 3, "KeyShare: Invalid length of clientShares field (minimum is 3 or 0 if empty)");

                while (!cursor.OnMaxPosition)
                {
                    cursor++;

                    SupportedGroupExtension.NamedGroup group = (SupportedGroupExtension.NamedGroup)MemMap.ToUShort2BytesBE(buffer, cursor);
                    cursor += 2;
                    ushort keyExchangeLength = MemMap.ToUShort2BytesBE(buffer, cursor);
                    cursor += 2;

                    validate.Handshake.KeyShare_KeyShareEntry_KeyExchangeLength(keyExchangeLength);

                    cursor.ThrowIfShiftOutside(keyExchangeLength - 1);
                    byte[] keyExchange = new byte[keyExchangeLength];
                    MemCpy.Copy(buffer, cursor, keyExchange, 0, keyExchangeLength);

                    KeyShareEntry entry  = new KeyShareEntry(group, keyExchange);

                    keyShareEntires.Add(entry);

                    cursor += keyExchangeLength - 1;
                }
            }

            if (!cursor.OnMaxPosition)
                validate.Handshake.ThrowGeneral("keyshare: after deserializing cursor is not on last position. " +
                    "individual length of all key shares not match extension length");

            return new KeyShareClientHelloExtension(keyShareEntires.ToArray());
        }

        private Extension DeserializeExtension_SupportedGroups(byte[] buffer, int offset)
        {
            ushort contentLength = MemMap.ToUShort2BytesBE(buffer, offset + 2);
            ushort namedCurveListLength;
            List<SupportedGroupExtension.NamedGroup> curves = new List<SupportedGroupExtension.NamedGroup>();

            int maxCursor = 4 + offset + contentLength - 1;

            if (contentLength < 4)
                validate.Extensions.ThrowGeneralException("Supported groups: invalid extensinos length, minimum should be 4");

            RangeCursor cursor = new RangeCursor(offset + 4, maxCursor);
            namedCurveListLength = MemMap.ToUShort2BytesBE(buffer, cursor);

            validate.Extensions.SupportedGroups_NamedCurveListLength(namedCurveListLength);
            cursor += 1;

            while (cursor < cursor.MaxPosition)
            {
                // now points to second byte of named curve (or first byte before first curve)
                // shift to point to first byte of curve
                cursor++;

                SupportedGroupExtension.NamedGroup namedCurve = (SupportedGroupExtension.NamedGroup)MemMap.ToUShort2BytesBE(buffer, cursor);

                curves.Add(namedCurve);

                // now points to second byte of named curve
                cursor++;
            }

            return new SupportedGroupExtension(curves.ToArray());
        }

        private Extension DeserializeExtension_SignatureAlgorithmsCert(byte[] buf, int offs)
        {
            SignatureSchemeListExtension ext = (SignatureSchemeListExtension)DeserializeExtension_SignatureAlgorithms(buf, offs);

            return new SignatureSchemeListExtension(ext.Schemes, ExtensionType.SignatureAlgorithmsCert);
        }

        private Extension DeserializeExtension_SignatureAlgorithms(byte[] buffer, int offset)
        {
            ushort length = MemMap.ToUShort2BytesBE(buffer, offset + 2);
            ushort supportedSignatureAlgorithmsLength;
            RangeCursor cursor = new RangeCursor(offset, 4 + length + offset - 1);
            List<SignatureSchemeListExtension.SignatureScheme> schemes = new List<SignatureSchemeListExtension.SignatureScheme>();

            if (length < 2) 
                validate.Extensions.ThrowGeneralException("Signature algorithms: invalid content length minimum 2");

            cursor += 4;
            supportedSignatureAlgorithmsLength = MemMap.ToUShort2BytesBE(buffer, cursor);

            validate.Handshake.SignatureAlgorithms_SupportedSignatureAlgoritmsLength(supportedSignatureAlgorithmsLength);

            for (int i = 0; i < supportedSignatureAlgorithmsLength; i += 2)
            {
                cursor += 2;
                SignatureSchemeListExtension.SignatureScheme scheme = (SignatureSchemeListExtension.SignatureScheme)MemMap.ToUShort2BytesBE(buffer, cursor);

                schemes.Add(scheme);
            }

            return new SignatureSchemeListExtension(schemes.ToArray(), ExtensionType.SignatureAlgorithms);
        }

        private Extension DeserializeExtension_Cookie(byte[] arg1, int arg2)
        {
            return null;
            throw new NotImplementedException();
        }

        private Extension DeserializeExtension_SupportedVersions_Server(byte[] buffer, int offset)
        {
            int length;
            RangeCursor cursor;
            ExtensionDeserializeSetup(buffer, offset, out cursor, out length);

            List<ushort> versions = new List<ushort>();
            ushort versionsLength = buffer[cursor];

            validate.Extensions.SupportedVersions_Client_VersionsLength(versionsLength);
            cursor.ThrowIfShiftOutside(versionsLength - 1);

            for (int i = 0; i < versionsLength; i += 2)
            {
                cursor++;

                versions.Add(MemMap.ToUShort2BytesBE(buffer, cursor));

                cursor++;
            }

            if (!cursor.OnMaxPosition)
                validate.Extensions.ThrowGeneralException("supported versions (client): cursor not at the end");

            return new ClientSupportedVersionsExtension(versions.ToArray());
        }

        private Extension DeserializeExtension_ALPN(byte[] buffer, int offset)
        {
            ushort contentLength = MemMap.ToUShort2BytesBE(buffer, offset + 2);
            ushort protocolNameListLength;
            List<byte[]> protocolNames = new List<byte[]>();

            RangeCursor cursor = new RangeCursor(offset + 4, offset + 4 + contentLength - 1);

            if (contentLength == 0)
                return new ProtocolNameListExtension(new byte[0][]);

            if (contentLength < 2)
                validate.Extensions.ThrowGeneralException("ALPN: Invalid lenght of extension content, minimum 2");

            protocolNameListLength = MemMap.ToUShort2BytesBE(buffer, cursor);
            validate.Extensions.ALPN_ProtocolNameListLength(protocolNameListLength);

            cursor += 1;

            while (cursor < cursor.MaxPosition)
            {
                cursor++;

                ushort protocolNameLength = buffer[cursor];
                validate.Extensions.ALPN_ProtocolNameLength(protocolNameLength);
                cursor += 1;

                cursor.ThrowIfShiftOutside(protocolNameLength - 1);
                byte[] protocolName = new byte[protocolNameLength];

                MemCpy.Copy(buffer, cursor, protocolName, 0, protocolNameLength);
                protocolNames.Add(protocolName);

                cursor += protocolNameLength - 1;
            }

            validate.Extensions.ThrowGeneral(!cursor.OnMaxPosition, "cursor not max");

            return new ProtocolNameListExtension(protocolNames.ToArray());
        }

        private void ExtensionDeserializeSetup(byte[] buffer, int offset, out RangeCursor cursor, out int length)
        {
            length = MemMap.ToUShort2BytesBE(buffer, offset + 2);

            if (length > 0)
            {
                cursor = new RangeCursor(offset + 4, offset + 4 + length - 1);
            }
            else
            {
                cursor = new RangeCursor(0, 0);
            }
        }

        public struct ExtensionDeserializeResult
        {
            public bool IsRecognized;
            public int Length;
            public Extension Extension;
        }

        #endregion

        private static int ToInt3BytesBE(byte[] buf, int offs)
        {
            return (buf[0 + offs] << 16) | (buf[1 + offs] << 8) | (buf[2 + offs]);
        }

        private void ThrowCursorOutside(int nextCursorPosition, int maxCursorPosition)
        {
            if (nextCursorPosition > maxCursorPosition)
                throw new API.Tls13Exception("next cursor position outside of bounds");
        }
    }
}
