using System;
using Arctium.Protocol.Tls.Protocol.HandshakeProtocol;
using System.Collections.Generic;
using Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Enum;
using Arctium.Protocol.Tls.Protocol.BinaryOps.Builder.Exceptions;

namespace Arctium.Protocol.Tls.Protocol.BinaryOps.Builder.HandshakeBuilders
{
    class HandshakeBuilder
    {
        static Dictionary<HandshakeType, HandshakeBuilderBase> typeToBuilderMap;

        static HandshakeBuilder()
        {
            typeToBuilderMap = new Dictionary<HandshakeType, HandshakeBuilderBase>();

            typeToBuilderMap[HandshakeType.ClientHello] = new ClientHelloBuilder();
            typeToBuilderMap[HandshakeType.ServerHello] = new ServerHelloBuilder();
            typeToBuilderMap[HandshakeType.Certificate] = new CertificateBuilder();
            typeToBuilderMap[HandshakeType.ServerKeyExchange] = new ServerKeyExchangeBuilder();
            typeToBuilderMap[HandshakeType.CertificateRequest] = new CertificateRequestBuilder();
            typeToBuilderMap[HandshakeType.ServerHelloDone] = new ServerHelloDoneBuilder();

            typeToBuilderMap[HandshakeType.ClientKeyExchange] = new ClientKeyExchangeBuilder();
            typeToBuilderMap[HandshakeType.CertificateVerify] = new CertificateVerifyBuilder();
            typeToBuilderMap[HandshakeType.Finished] = new FinishedBuilder();
        }


        static HandshakeBuilderBase GetBuilder(HandshakeType type)
        {
            return typeToBuilderMap[type];
        }

        public HandshakeBuilder() { }

        public Handshake GetHandshake(byte[] buffer, int offset)
        {
            HandshakeType handshakeType = GetHandshakeType(buffer, offset + ProtocolFormatConst.HandshakeTypeOffset);
            int handshakeContentLength = (int)NumberConverter.ToUInt24(buffer, offset + ProtocolFormatConst.HandshakeLengthOffset);
            int messageOffset = offset + ProtocolFormatConst.HandshakeHeaderLength;

            HandshakeBuilderBase builder = GetBuilder(handshakeType);

            return builder.BuildFromBytes(buffer, offset + 4, handshakeContentLength);
        }

        private void ThrowUnrecognizedHandshakeTypeException(byte value)
        {
            string msg = "ERROR::HandshakeBuilder:: Unrecognized 'Handshake Type'. {0} is not associated with any 'HandshakeType' enum value.";
            throw new MessageFromatException(msg);
        }

        private HandshakeType GetHandshakeType(byte[] buffer, int offset)
        {
            byte type = buffer[offset];
            
            if (!Enum.IsDefined(typeof(HandshakeType), type)) ThrowUnrecognizedHandshakeTypeException(type);

            return (HandshakeType)type;

        }
    }
}
