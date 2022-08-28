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
        byte[] temp;
        Dictionary<Type, Action<object>> serializers = new Dictionary<Type, Action<object>>();

        public byte[] SerializedData { get { return buffer.Buffer; } }
        public long SerializedDataLength { get { return buffer.DataLength; } }

        public ModelSerialization()
        {
            buffer = new ByteBuffer();
            temp = new byte[16];

            InitSerializers();
        }

        private void InitSerializers()
        {
            serializers = new Dictionary<Type, Action<object>>()
            {
                [typeof(ServerHello)] = SerializeServerHello
            };
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
                ToBytes(extension);
            }

            // serialized extensions length (-2 because 2 bytes to store this computed length before serialized extensions)
            int extensionsLength = (buffer.DataLength - setExtensionsLengthOffset + 1) - 2;

            MemMap.ToBytes1UShortBE((ushort)extensionsLength, buffer.Buffer, setExtensionsLengthOffset);

            // -3 because 3 bytes to store length
            int fullLength = (buffer.DataLength - setMessageLengthOffset + 1) - 3;

            buffer.Buffer[setMessageLengthOffset + 0] = (byte)(fullLength >> 16);
            buffer.Buffer[setMessageLengthOffset + 1] = (byte)(fullLength >> 08);
            buffer.Buffer[setMessageLengthOffset + 2] = (byte)(fullLength >> 00);

            if (fullLength > (2 << 24)) throw new Exception("INTERNAL TLS 1.3: something is wrong with serialization, handshake serialized length > 2^24");
        }
    }
}
