using Arctium.Connection.Tls.Tls13.API;
using Arctium.Connection.Tls.Tls13.Model;
using Arctium.Connection.Tls.Tls13.Model.Extensions;
using Arctium.Shared.Helpers.Buffers;
using System;
using System.Collections.Generic;

namespace Arctium.Connection.Tls.Tls13.Protocol
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
                [typeof(EncryptedExtensions)] = SerializeCertificate,
                [typeof(CertificateVerify)] = SerializeCertificateVerify,
                [typeof(Finished)] = SerializeFinished,
            };

            singleExtensionSerializers = new Dictionary<Type, Action<object>>
            {
                [typeof(ServerSupportedVersionsExtension)] = SerializeServerSupportedVersionExtension,
                [typeof(KeyShareServerHelloExtension)] = SerializeKeyShareServerHelloExtension,
                [typeof(EncryptedExtensions)] = SerializeEncryptedExtensions,
                [typeof(ProtocolNameListExtension)] = SerializeProtocolNameListExtension,
            };
        }

        private void SerializeFinished(object obj)
        {
            Finished fin = (Finished)obj;

            buffer.Append((byte)HandshakeType.Finished);
            int msgLenOffs = buffer.OutsideAppend(3);

            int verDataOffs = buffer.OutsideAppend(fin.VerifyData.Length);
            MemCpy.Copy(fin.VerifyData, 0, SerializedData, verDataOffs, fin.VerifyData.Length);

            int msgLen = (int)(SerializedDataLength - msgLenOffs + 1 - 3);
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

            int msgLen = (int)(SerializedDataLength - msgLenOffs + 1) - 3;
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
                if (certEntry.CertificateType != CertificateType.X509) throw new Exception("internal: not implemented other that x509");

                int certLenOffs = buffer.OutsideAppend(3);
                int certLen = certEntry.CertData.Length;
                int certOffs = buffer.OutsideAppend(certLen);

                SerializedData[certLenOffs + 0] = (byte)((certLen & 0xFF0000) >> 16);
                SerializedData[certLenOffs + 1] = (byte)((certLen & 0x00FF00) >> 08);
                SerializedData[certLenOffs + 2] = (byte)((certLen & 0x0000FF) >> 00);

                MemCpy.Copy(certEntry.CertData, 0, SerializedData, certOffs, certLen);

                certListLen += 3 + certLen;
            }

            if (certListLen > 0x00FFFFFF) throw new Exception("internal: cert list > 2^24");


            Set3Bytes(certListLen, certListLenOffs);

            long msgLen = (SerializedDataLength - msgLenOffs + 1) - 3;

            Set3Bytes((int)msgLen, msgLenOffs);
        }

        private void Set3Bytes(int v, int offset)
        {
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

                int nameLenOffs = tempSerializedExtension.OutsideAppend(2);
                int protNameOffs = tempSerializedExtension.OutsideAppend(protName.Length);
                MemCpy.Copy(protName, 0, tempSerializedExtension.Buffer, protNameOffs, protName.Length);
                MemMap.ToBytes1UShortBE((ushort)protName.Length, tempSerializedExtension.Buffer, nameLenOffs);

                totalLen += 2 + protName.Length;
            }

            if (totalLen > (1 << 16) - 1) throw new Exception("internal: totalLen exceed 2^16 - 1");

            MemMap.ToBytes1UShortBE((ushort)listLenOffs, tempSerializedExtension.Buffer, listLenOffs);
        }

        private void SerializeEncryptedExtensions(object obj)
        {
            EncryptedExtensions encExt = (EncryptedExtensions)obj;

            buffer.Append((byte)HandshakeType.EncryptedExtensions);
            int lenOffs = buffer.OutsideAppend(3);

            foreach (var ext in encExt.Extensions) { ExtensionToBytes(ext); }

            // -3 3 bytes to store extension length
            long extLen = (SerializedDataLength - lenOffs + 1) - 3;

            SerializedData[lenOffs + 0] = (byte)((extLen & 0xFF0000) >> 16);
            SerializedData[lenOffs + 1] = (byte)((extLen & 0x00FF00) >> 08);
            SerializedData[lenOffs + 2] = (byte)((extLen & 0x0000FF) >> 00);
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

            tempSerializedExtension.OutsideAppend(2);
            MemMap.ToBytes1UShortBE(extension.SelectedVersion, buffer.Buffer, buffer.DataLength - 2);
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

        public void SingleExtensionToBytes(object msg)
        {
            if (msg == null) throw new ArgumentNullException("msg");

            if (!singleExtensionSerializers.ContainsKey(msg.GetType())) throw new NotImplementedException($"Serialization method for '{msg.GetType().Name}' is not implemented");

            singleExtensionSerializers[msg.GetType()](msg);
        }

        private void ExtensionToBytes(object ext)
        {
            tempSerializedExtension.Reset();

            Extension extension = (Extension)ext;
            SingleExtensionToBytes(ext);

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
