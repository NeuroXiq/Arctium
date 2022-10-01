using Arctium.Standards.Connection.Tls.Tls13.API;
using Arctium.Standards.Connection.Tls.Tls13.Model;
using Arctium.Standards.Connection.Tls.Tls13.Model.Extensions;
using Arctium.Shared.Exceptions;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Shared.Other;
using System;
using System.Collections.Generic;
using Arctium.Shared.Helpers;

namespace Arctium.Standards.Connection.Tls.Tls13.Protocol
{
    internal class ModelSerialization
    {
        ByteBuffer buffer;
        ByteBuffer tempSerializedExtension;
        byte[] temp;
        Dictionary<Type, Action<object>> serializers = new Dictionary<Type, Action<object>>();
        Dictionary<Type, Action<object>> singleExtensionSerializers = new Dictionary<Type, Action<object>>();

        public byte[] SerializedData { get { return buffer.Buffer; } }
        public long SerializedDataLength { get { return buffer.DataLength; } }

        public ModelSerialization()
        {
            buffer = new ByteBuffer();
            tempSerializedExtension = new ByteBuffer();
            temp = new byte[16];

            InitSerializers();
        }

        private void InitSerializers()
        {
            serializers = new Dictionary<Type, Action<object>>()
            {
                [typeof(ServerHello)] = SerializeServerHello,
                [typeof(Certificate)] = SerializeCertificate,
                [typeof(CertificateVerify)] = SerializeCertificateVerify,
                [typeof(Finished)] = SerializeFinished,
                [typeof(EncryptedExtensions)] = SerializeEncryptedExtensions,
                [typeof(NewSessionTicket)] = SerializeNewSessionTicket,
                [typeof(CertificateRequest)] = SerializeCertificateRequest,
                [typeof(ClientHello)] = SerializeClientHello
            };

            singleExtensionSerializers = new Dictionary<Type, Action<object>>
            {
                [typeof(ServerSupportedVersionsExtension)] = SerializeServerSupportedVersionExtension,
                [typeof(KeyShareServerHelloExtension)] = SerializeKeyShareServerHelloExtension,
                [typeof(ProtocolNameListExtension)] = SerializeProtocolNameListExtension,
                [typeof(PreSharedKeyServerHelloExtension)] = Serialize_Extension_PreSharedKeyServerHelloExtension,
                [typeof(KeyShareHelloRetryRequestExtension)] = Serialize_Extension_KeyShareHelloRetryRequestExtension,
                [typeof(CookieExtension)] = Serialize_Extension_Cookie,
                [typeof(SignatureSchemeListExtension)] = Serialize_Extension_SignatureSchemeListExtension,
                [typeof(ClientSupportedVersionsExtension)] = Serialize_Extension_ClientSupportedVersionsExtension,
                [typeof(KeyShareClientHelloExtension)] = Serialize_Extension_KeyShareClientHelloExtension,
                [typeof(SupportedGroupExtension)] = Serialize_Extension_SupportedGroupExtension,
            };
        }

        private void Serialize_Extension_SupportedGroupExtension(object obj)
        {
            SupportedGroupExtension ext = (SupportedGroupExtension)obj;

            int groupLen = ext.NamedGroupList.Length * 2;
            int namedGroupListLenOffs = tempSerializedExtension.OutsideAppend(2);

            MemMap.ToBytes1UShortBE((ushort)groupLen,
                tempSerializedExtension.Buffer,
                namedGroupListLenOffs);

            for (int i = 0; i < ext.NamedGroupList.Length; i++)
            {
                int groupOffs = tempSerializedExtension.OutsideAppend(2);
                MemMap.ToBytes1UShortBE((ushort)ext.NamedGroupList[i], tempSerializedExtension.Buffer, groupOffs);
            }

        }

        private void Serialize_Extension_KeyShareClientHelloExtension(object obj)
        {
            KeyShareClientHelloExtension ext = (KeyShareClientHelloExtension)obj;

            int clientSharesVectorLenOffs = tempSerializedExtension.OutsideAppend(2);

            for (int i = 0; i < ext.ClientShares.Length; i++)
            {
                var share = ext.ClientShares[i];
                int groupOffs = tempSerializedExtension.OutsideAppend(2);
                int keyExLenOffs = tempSerializedExtension.OutsideAppend(2);
                int keyExOffs = tempSerializedExtension.OutsideAppend(share.KeyExchangeRawBytes.Length);

                MemMap.ToBytes1UShortBE((ushort)share.KeyExchangeRawBytes.Length, tempSerializedExtension.Buffer, keyExLenOffs);
                MemMap.ToBytes1UShortBE((ushort)share.NamedGroup, tempSerializedExtension.Buffer, groupOffs);
                
                MemCpy.Copy(share.KeyExchangeRawBytes, 0,
                    tempSerializedExtension.Buffer, keyExOffs,
                    share.KeyExchangeRawBytes.Length);
            }

            int sharesLen = tempSerializedExtension.DataLength - 2 - clientSharesVectorLenOffs;

            Validation.ThrowInternal(sharesLen > Tls13Const.KeyShareClientHello_ClientSharesVectorMaxLen);

            MemMap.ToBytes1UShortBE((ushort)sharesLen, tempSerializedExtension.Buffer, clientSharesVectorLenOffs);
        }

        private void Serialize_Extension_ClientSupportedVersionsExtension(object obj)
        {
            ClientSupportedVersionsExtension ext = (ClientSupportedVersionsExtension)obj;

            int versionsVectorLen = ext.Versions.Length * 2;
            tempSerializedExtension.Append((byte)versionsVectorLen);

            for (int i = 0; i < ext.Versions.Length; i++)
            {
                int verOffs = tempSerializedExtension.OutsideAppend(2);
                MemMap.ToBytes1UShortBE(ext.Versions[i], tempSerializedExtension.Buffer, verOffs);
            }
        }

        private void SerializeClientHello(object obj)
        {
            ClientHello hello = (ClientHello)obj;

            buffer.Append((byte)HandshakeType.ClientHello);
            int lenOffs = buffer.OutsideAppend(3);

            int versionOffs = buffer.OutsideAppend(2);
            MemMap.ToBytes1UShortBE((hello.ProtocolVersion), SerializedData, versionOffs);

            int randomOffs = buffer.OutsideAppend(hello.Random.Length);
            MemCpy.Copy(hello.Random, 0, SerializedData, randomOffs, hello.Random.Length);

            AppendVector(hello.LegacySessionId, 1, Tls13Const.ClientHello_LegacySessionIdMaxLen);

            int cipherSuiteLenOffs = buffer.OutsideAppend(2);
            int ciphSuiteLen = 2 * hello.CipherSuites.Length;
            MemMap.ToBytes1UShortBE((ushort)(ciphSuiteLen), SerializedData, cipherSuiteLenOffs);

            for (int i = 0; i < hello.CipherSuites.Length; i++)
            {
                int ciphOffs = buffer.OutsideAppend(2);
                MemMap.ToBytes1UShortBE((ushort)hello.CipherSuites[i], SerializedData, ciphOffs);
            }

            AppendVector(hello.LegacyCompressionMethods, 1, 1);

            int extensionsLenOffs = buffer.OutsideAppend(2);

            foreach (var ext in hello.Extensions) ExtensionToBytes(ext);

            int extensionsLen = (int)(SerializedDataLength - extensionsLenOffs - 2);
            MemMap.ToBytes1UShortBE((ushort)extensionsLen, SerializedData, extensionsLenOffs);

            Set3Bytes((int)(SerializedDataLength - lenOffs - 3), lenOffs);
        }

        private void AppendVector(byte[] vectorData, int vectorLengthBytesCount, int validateMaxLength)
        {
            Validation.ThrowInternal(validateMaxLength < vectorData.Length);

            int lenOffs = buffer.OutsideAppend(vectorLengthBytesCount);
            int vectorLen = vectorData.Length;
            int dataOffs = buffer.OutsideAppend(vectorLen);

            if (vectorLengthBytesCount == 3) Set3Bytes(vectorLen, lenOffs);
            else if (vectorLengthBytesCount == 2) MemMap.ToBytes1UShortBE((ushort)vectorLen, SerializedData, lenOffs);
            else if (vectorLengthBytesCount == 1) SerializedData[lenOffs] = (byte)vectorLen;
            else Validation.ThrowInternal();

            MemCpy.Copy(vectorData, 0, SerializedData, dataOffs, vectorLen);
        }

        private void SerializeCertificateRequest(object obj)
        {
            CertificateRequest certReq = (CertificateRequest)obj;

            buffer.Append((byte)HandshakeType.CertificateRequest);
            int handshakeLenOffset = buffer.OutsideAppend(3);

            int reqContextLen = certReq.CertificateRequestContext.Length;

            Validation.ThrowInternal(reqContextLen > 255);
            
            buffer.Append((byte)reqContextLen);
            int contextOffset = buffer.OutsideAppend(reqContextLen);

            MemCpy.Copy(certReq.CertificateRequestContext, 0, buffer.Buffer, contextOffset, reqContextLen);

            int extLenOffs = buffer.OutsideAppend(2);

            foreach (var ext in certReq.Extensions) ExtensionToBytes(ext);

            long extLen = SerializedDataLength - extLenOffs - 2;

            Validation.ThrowInternal(extLen > ushort.MaxValue);

            MemMap.ToBytes1UShortBE((ushort)extLen, SerializedData, extLenOffs);

            Set3Bytes((int)(SerializedDataLength - handshakeLenOffset - 3), handshakeLenOffset);
        }

        private void Serialize_Extension_SignatureSchemeListExtension(object obj)
        {
            SignatureSchemeListExtension ext = (SignatureSchemeListExtension)obj;

            Validation.ThrowInternal(ext.Schemes.Length == 0, "spec say min one scheme");

            int lenOffs = tempSerializedExtension.OutsideAppend(2);

            for (int i = 0; i < ext.Schemes.Length; i++)
            {
                int schemeOffs = tempSerializedExtension.OutsideAppend(2);
                MemMap.ToBytes1UShortBE((ushort)ext.Schemes[i], tempSerializedExtension.Buffer, schemeOffs);
            }

            MemMap.ToBytes1UShortBE((ushort)(ext.Schemes.Length * 2), tempSerializedExtension.Buffer, lenOffs);
        }

        private void Serialize_Extension_Cookie(object obj)
        {
            CookieExtension ext = (CookieExtension)obj;

            int lenOffs = tempSerializedExtension.OutsideAppend(2);
            int o = tempSerializedExtension.OutsideAppend(ext.Cookie.Length);

            if (ext.Cookie.Length > ushort.MaxValue) throw new ArctiumExceptionInternal();

            MemMap.ToBytes1UShortBE((ushort)ext.Cookie.Length, tempSerializedExtension.Buffer, lenOffs);
            MemCpy.Copy(ext.Cookie, 0, tempSerializedExtension.Buffer, o, ext.Cookie.Length);
        }

        private void Serialize_Extension_KeyShareHelloRetryRequestExtension(object obj)
        {
            KeyShareHelloRetryRequestExtension ext = (KeyShareHelloRetryRequestExtension)obj;

            int groupOffs = tempSerializedExtension.OutsideAppend(2);

            MemMap.ToBytes1UShortBE((ushort)ext.SelectedGroup, tempSerializedExtension.Buffer, groupOffs);
        }

        private void Serialize_Extension_PreSharedKeyServerHelloExtension(object obj)
        {
            PreSharedKeyServerHelloExtension ext = (PreSharedKeyServerHelloExtension)obj;

            int offset = tempSerializedExtension.OutsideAppend(2);

            MemMap.ToBytes1UShortBE(ext.SelectedIdentity, tempSerializedExtension.Buffer, offset);
        }

        private void SerializeNewSessionTicket(object obj)
        {
            NewSessionTicket ticket = (NewSessionTicket)obj;

            buffer.Append((byte)(HandshakeType.NewSessionTicket));
            int msgLenOffs = buffer.OutsideAppend(3);
            int msgLen = -1;

            int ticketLifetimeOffs = buffer.OutsideAppend(4);
            int ticketAgeAddOffs = buffer.OutsideAppend(4);
            int ticketNonceLenOffs = buffer.OutsideAppend(1);
            int ticketNonceOffs = buffer.OutsideAppend(ticket.TicketNonce.Length);
            int ticketLenOffs = buffer.OutsideAppend(2);
            int ticketOffs = buffer.OutsideAppend(ticket.Ticket.Length);
            int extensionsLenOffs = buffer.OutsideAppend(2);
            int extensionsLen = -1;

            foreach (var extension in ticket.Extensions) ExtensionToBytes(extension);

            extensionsLen = (int)(SerializedDataLength - extensionsLenOffs - 2);

            MemMap.ToBytes1UIntBE(ticket.TicketLifetime, SerializedData, ticketLifetimeOffs);
            MemMap.ToBytes1UIntBE(ticket.TicketAgeAdd, SerializedData, ticketAgeAddOffs);
            SerializedData[ticketNonceLenOffs] = (byte)ticket.TicketNonce.Length;
            MemCpy.Copy(ticket.TicketNonce, 0, SerializedData, ticketNonceOffs, ticket.TicketNonce.Length);
            MemMap.ToBytes1UShortBE((ushort)ticket.Ticket.Length, SerializedData, ticketLenOffs);
            MemCpy.Copy(ticket.Ticket, 0, SerializedData, ticketOffs, ticket.Ticket.Length);
            MemMap.ToBytes1UShortBE((ushort)extensionsLen, SerializedData, extensionsLenOffs);

            msgLen = (int)(SerializedDataLength - msgLenOffs - 3);
            Set3Bytes(msgLen, msgLenOffs);
        }

        private void SerializeFinished(object obj)
        {
            Finished fin = (Finished)obj;

            buffer.Append((byte)HandshakeType.Finished);
            int msgLenOffs = buffer.OutsideAppend(3);

            int verDataOffs = buffer.OutsideAppend(fin.VerifyData.Length);
            MemCpy.Copy(fin.VerifyData, 0, SerializedData, verDataOffs, fin.VerifyData.Length);

            int msgLen = (int)(SerializedDataLength - msgLenOffs - 3);
            Set3Bytes(msgLen, msgLenOffs);
        }

        private void SerializeCertificateVerify(object obj)
        {
            CertificateVerify ver = (CertificateVerify)obj;
            buffer.Append((byte)(HandshakeType.CertificateVerify));
            int msgLenOffs = buffer.OutsideAppend(3);

            int schemOffs = buffer.OutsideAppend(2);
            int sigLenOffs = buffer.OutsideAppend(2);
            int sigOffs = buffer.OutsideAppend(ver.Signature.Length);

            MemMap.ToBytes1UShortBE((ushort)ver.SignatureScheme, SerializedData, schemOffs);
            MemMap.ToBytes1UShortBE((ushort)ver.Signature.Length, SerializedData, sigLenOffs);
            MemCpy.Copy(ver.Signature, 0, SerializedData, sigOffs, ver.Signature.Length);

            int msgLen = (int)(SerializedDataLength - msgLenOffs) - 3;
            Set3Bytes(msgLen, msgLenOffs);
        }

        private void SerializeCertificate(object obj)
        {
            Certificate cert = (Certificate)obj;

            buffer.Append((byte)HandshakeType.Certificate);
            int msgLenOffs = buffer.OutsideAppend(3);

            int lenOffs = buffer.OutsideAppend(1);
            int reqCtxOffs = buffer.OutsideAppend(cert.CertificateRequestContext.Length);
            
            SerializedData[lenOffs] = (byte)(cert.CertificateRequestContext.Length);
            MemCpy.Copy(cert.CertificateRequestContext, 0, SerializedData, reqCtxOffs, cert.CertificateRequestContext.Length);

            int certListLen = 0;
            int certListLenOffs = buffer.OutsideAppend(3);

            foreach (var certEntry in cert.CertificateList)
            {
                if (certEntry.CertificateType != null) throw new Exception("internal: not implemented other that x509, not sure how to serialize/deserialize, now it must be null until something better found");

                int certLenOffs = buffer.OutsideAppend(3);
                int certLen = certEntry.CertificateEntryRawBytes.Length;
                int certOffs = buffer.OutsideAppend(certLen);
                int extLenOffs = buffer.OutsideAppend(2);

                SerializedData[certLenOffs + 0] = (byte)((certLen & 0xFF0000) >> 16);
                SerializedData[certLenOffs + 1] = (byte)((certLen & 0x00FF00) >> 08);
                SerializedData[certLenOffs + 2] = (byte)((certLen & 0x0000FF) >> 00);

                MemCpy.Copy(certEntry.CertificateEntryRawBytes, 0, SerializedData, certOffs, certLen);

                if (certEntry.Extensions.Length > 0) throw new NotImplementedException("extesnsions serialization not implemented");
                MemMap.ToBytes1UShortBE(0, SerializedData, extLenOffs);

                // certListLen += 3 + certLen;
            }

            certListLen = (int)(SerializedDataLength - certListLenOffs - 3);

            if (certListLen > 0x00FFFFFF) throw new Exception("internal: cert list > 2^24");

            Set3Bytes(certListLen, certListLenOffs);

            long msgLen = (SerializedDataLength - msgLenOffs) - 3;

            Set3Bytes((int)msgLen, msgLenOffs);
        }

        private void Set3Bytes(int v, int offset)
        {
            if (((0xFF000000) & v) != 0) Validation.ThrowInternal();

            SerializedData[offset + 0] = (byte)((v & 0xFF0000) >> 16);
            SerializedData[offset + 1] = (byte)((v & 0x00FF00) >> 08);
            SerializedData[offset + 2] = (byte)((v & 0x0000FF) >> 00);
        }

        private void SerializeProtocolNameListExtension(object obj)
        {
            ProtocolNameListExtension ext = (ProtocolNameListExtension)obj;

            int totalLen = 0;

            int listLenOffs = tempSerializedExtension.OutsideAppend(2);

            for (int i = 0; i < ext.ProtocolNamesList.Length; i++)
            {
                byte[] protName = ext.ProtocolNamesList[i];

                if (protName.Length > 255) throw new Exception("internal: ALPN protocol name len > 255");

                int nameLenOffs = tempSerializedExtension.OutsideAppend(1);
                int protNameOffs = tempSerializedExtension.OutsideAppend(protName.Length);
                MemCpy.Copy(protName, 0, tempSerializedExtension.Buffer, protNameOffs, protName.Length);
                tempSerializedExtension.Buffer[nameLenOffs] = (byte)protName.Length;

                totalLen += 1 + protName.Length;
            }

            if (totalLen > (1 << 16) - 1) throw new Exception("internal: totalLen exceed 2^16 - 1");

            MemMap.ToBytes1UShortBE((ushort)totalLen, tempSerializedExtension.Buffer, listLenOffs);
        }

        private void SerializeEncryptedExtensions(object obj)
        {
            EncryptedExtensions encExt = (EncryptedExtensions)obj;

            buffer.Append((byte)HandshakeType.EncryptedExtensions);
            int msgLenOffs = buffer.OutsideAppend(3);
            int extLenOffs = buffer.OutsideAppend(2);

            foreach (var ext in encExt.Extensions) { ExtensionToBytes(ext); }

            // -3 3 bytes to store extension length
            long extLen = (SerializedDataLength - extLenOffs) - 2;
            long msgLen = (SerializedDataLength - msgLenOffs) - 3;

            SerializedData[extLenOffs + 0] = (byte)((extLen & 0xFF00) >> 8);
            SerializedData[extLenOffs + 1] = (byte)((extLen & 0x00FF) >> 0);

            SerializedData[msgLenOffs + 0] = (byte)((msgLen & 0xFF0000) >> 16);
            SerializedData[msgLenOffs + 1] = (byte)((msgLen & 0x00FF00) >> 08);
            SerializedData[msgLenOffs + 2] = (byte)((msgLen & 0x0000FF) >> 00);
        }

        private void SerializeKeyShareServerHelloExtension(object obj)
        {
            KeyShareServerHelloExtension ext = (KeyShareServerHelloExtension)obj;

            int groupOffset = tempSerializedExtension.OutsideAppend(2);
            int lenOffs = tempSerializedExtension.OutsideAppend(2);
            int keyExchOffs = tempSerializedExtension.OutsideAppend(ext.ServerShare.KeyExchangeRawBytes.Length);
            
            MemMap.ToBytes1UShortBE((ushort)ext.ServerShare.NamedGroup, tempSerializedExtension.Buffer, groupOffset);
            MemMap.ToBytes1UShortBE((ushort)ext.ServerShare.KeyExchangeRawBytes.Length, tempSerializedExtension.Buffer, lenOffs);
            MemCpy.Copy(ext.ServerShare.KeyExchangeRawBytes, 0, tempSerializedExtension.Buffer, keyExchOffs, ext.ServerShare.KeyExchangeRawBytes.Length);
        }

        private void SerializeServerSupportedVersionExtension(object obj)
        {
            ServerSupportedVersionsExtension extension = (ServerSupportedVersionsExtension)obj;

            int offs = tempSerializedExtension.OutsideAppend(2);
            MemMap.ToBytes1UShortBE(extension.SelectedVersion, tempSerializedExtension.Buffer, offs);
        }

        public void Reset()
        {
            buffer.Reset();
        }

        public void ToBytes(object msg)
        {
            if (msg == null) throw new ArgumentNullException("msg");
            
            if (!serializers.ContainsKey(msg.GetType())) throw new NotImplementedException($"Serialization method for '{msg.GetType().Name}' is not implemented");

            serializers[msg.GetType()](msg);
        }

        public void ExtensionContentToBytes(object msg)
        {
            if (msg == null) throw new ArgumentNullException("msg");

            if (!singleExtensionSerializers.ContainsKey(msg.GetType())) throw new NotImplementedException($"Serialization method for '{msg.GetType().Name}' is not implemented");

            singleExtensionSerializers[msg.GetType()](msg);
        }

        private void ExtensionToBytes(object ext)
        {
            tempSerializedExtension.Reset();

            Extension extension = (Extension)ext;
            ExtensionContentToBytes(ext);

            if (tempSerializedExtension.DataLength >= (1 << 16)) throw new Exception("internal: extension length > 2^16");

            buffer.Append(0, 0);
            MemMap.ToBytes1UShortBE((ushort)extension.ExtensionType, SerializedData, SerializedDataLength - 2);
            buffer.Append(0, 0);
            MemMap.ToBytes1UShortBE((ushort)tempSerializedExtension.DataLength, SerializedData, SerializedDataLength - 2);
            int contextOffset = buffer.OutsideAppend(tempSerializedExtension.DataLength);
            MemCpy.Copy(tempSerializedExtension.Buffer, 0, SerializedData, contextOffset, tempSerializedExtension.DataLength);
        }

        private void SerializeServerHello(object msg)
        {
            ServerHello serverHello = msg as ServerHello;

            temp[0] = (byte)HandshakeType.ServerHello;
            buffer.Append(temp, 0, 1);
            int setMessageLengthOffset = buffer.DataLength;
            
            // write everything and later compute length
            temp[0] = temp[1] = temp[2] = 0;
            buffer.Append(temp, 0, 3);

            MemMap.ToBytes1UShortBE(ServerHello.LegacyVersion, temp, 0);
            buffer.Append(temp, 0, 2);

            buffer.Append(serverHello.Random, 0, serverHello.Random.Length);
            buffer.Append((byte)serverHello.LegacySessionIdEcho.Length);
            buffer.Append(serverHello.LegacySessionIdEcho, 0, serverHello.LegacySessionIdEcho.Length);

            MemMap.ToBytes1UShortBE((ushort)serverHello.CipherSuite, temp, 0);
            buffer.Append(temp, 0, 2);

            temp[0] = ServerHello.LegacyCompressionMethod;
            buffer.Append(temp, 0, 1);

            int setExtensionsLengthOffset = buffer.DataLength;
            temp[0] = temp[1] = 0;
            buffer.Append(temp, 0, 2);

            foreach (var extension in serverHello.Extensions)
            {
                ExtensionToBytes(extension);
            }

            // serialized extensions length (-2 because 2 bytes to store this computed length before serialized extensions)
            int extensionsLength = (buffer.DataLength - setExtensionsLengthOffset) - 2;

            MemMap.ToBytes1UShortBE((ushort)extensionsLength, buffer.Buffer, setExtensionsLengthOffset);

            // -3 because 3 bytes to store length
            int fullLength = (buffer.DataLength - setMessageLengthOffset) - 3;

            buffer.Buffer[setMessageLengthOffset + 0] = (byte)(fullLength >> 16);
            buffer.Buffer[setMessageLengthOffset + 1] = (byte)(fullLength >> 08);
            buffer.Buffer[setMessageLengthOffset + 2] = (byte)(fullLength >> 00);

            if (fullLength > (1 << 24)) throw new Exception("INTERNAL TLS 1.3: something is wrong with serialization, handshake serialized length > 2^24");
        }
    }
}
