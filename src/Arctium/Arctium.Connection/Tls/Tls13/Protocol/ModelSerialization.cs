using Arctium.Connection.Tls.Tls13.API;
using Arctium.Connection.Tls.Tls13.Model;
using Arctium.Connection.Tls.Tls13.Model.Extensions;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Buffers;
using System;
using System.Collections.Generic;

namespace Arctium.Connection.Tls.Tls13.Protocol
{
    class ModelSerialization
    {
        private Validate validate;
        private Dictionary<ExtensionType, Func<byte[], int, Extension>> extensionsDeserialize;
        private Dictionary<ExtensionType, Func<byte[], int, Extension>> extensionsDeserializeClient;

        public ModelSerialization(Validate validate)
        {
            this.validate = validate;

            extensionsDeserialize = new Dictionary<ExtensionType, Func<byte[], int, Extension>>()
            {
                [ExtensionType.ApplicationLayerProtocolNegotiation] = DeserializeExtension_ALPN,
                [ExtensionType.Cookie] = DeserializeExtension_Cookie,
                [ExtensionType.SignatureAlgorithms] = DeserializeExtension_SignatureAlgorithms,
                [ExtensionType.SignatureAlgorithmsCert] = DeserializeExtension_SignatureAlgorithmsCert,
                [ExtensionType.SupportedGroups] = DeserializeExtension_SupportedGroups,
                [ExtensionType.KeyShare] = DeserializeExtension_KeyShare,
                [ExtensionType.ServerName] = DeserializeExtension_ServerName,
            };

            extensionsDeserializeClient = new Dictionary<ExtensionType, Func<byte[], int, Extension>>()
            {
                [ExtensionType.SupportedVersions] = DeserializeExtension_SupportedVersions_Client,
            };
        }

        #region Extensions

        public ExtensionDeserializeResult DeserializeExtension(byte[] buffer, int offset, int maxLength, bool isClient)
        {
            if (maxLength < 4)
                validate.Extensions.ThrowGeneralException(string.Format("Invalid extension length, minimum is 4 but current: {0}", maxLength));

            ExtensionType extensionType = (ExtensionType)MemMap.ToUShort2BytesBE(buffer, offset);
            ushort extensionLength = MemMap.ToUShort2BytesBE(buffer, offset + 2);
            int totalExtensionLength = extensionLength + 4;

            if (totalExtensionLength > maxLength)
                validate.Extensions.ThrowGeneralException(String.Format("Invalid extension lenght. Extension length exceed maximum length that is expected for that extension"));

            ExtensionDeserializeResult result;
            Extension extension;

            if (isClient && extensionsDeserializeClient.ContainsKey(extensionType))
            {
                extension = extensionsDeserializeClient[extensionType](buffer, offset);
            }
            else if (!extensionsDeserialize.ContainsKey(extensionType))
            {
                extension = new UnknowExtension(extensionType);
            }
            else
            {
                extension = extensionsDeserialize[extensionType](buffer, offset);
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

            return new ServerNameListExtension(serverNameList.ToArray());
        }

        private Extension DeserializeExtension_KeyShare(byte[] buffer, int offset)
        {
            int length;
            RangeCursor cursor;

            ExtensionDeserializeSetup(buffer, offset, out cursor, out length);

            if (length < 2)
                validate.Handshake.ThrowGeneral("key share: content length less than 2");

            ushort clientSharedLength = MemMap.ToUShort2BytesBE(buffer, cursor);
            List<KeyShareClientHelloExtension.KeyShareEntry> keyShareEntires = new List<KeyShareClientHelloExtension.KeyShareEntry>();

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

                    keyShareEntires.Add(new KeyShareClientHelloExtension.KeyShareEntry(group, keyExchange));

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
            List<NamedCurveListExtension.NamedCurve> curves = new List<NamedCurveListExtension.NamedCurve>();

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

                NamedCurveListExtension.NamedCurve namedCurve = (NamedCurveListExtension.NamedCurve)MemMap.ToUShort2BytesBE(buffer, cursor);

                curves.Add(namedCurve);

                // now points to second byte of named curve
                cursor++;
            }

            return new NamedCurveListExtension(curves.ToArray());
        }

        private Extension DeserializeExtension_SignatureAlgorithmsCert(byte[] arg1, int arg2)
        {
            throw new NotImplementedException();
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

            return new SignatureSchemeListExtension(schemes.ToArray());
        }

        private Extension DeserializeExtension_Cookie(byte[] arg1, int arg2)
        {
            throw new NotImplementedException();
        }

        private Extension DeserializeExtension_SupportedVersions_Client(byte[] buffer, int offset)
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

            return new SupportedVersionsExtension(versions.ToArray());
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

        private void ThrowCursorOutside(int nextCursorPosition, int maxCursorPosition)
        {
            if (nextCursorPosition > maxCursorPosition)
                throw new Tls13Exception("next cursor position outside of bounds");
        }
    }
}
