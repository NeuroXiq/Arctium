using System;
using Arctium.Connection.Tls.Protocol;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Builder
{
    class HandshakeBuilder
    {
        public HandshakeBuilder() { }


        public Handshake GetHandshake(byte[] buffer, int offset)
        {
            HandshakeType handshakeType = ParseHandshakeType(buffer, offset + ProtocolFormatConst.HandshakeTypeOffset);

            int handshakeContentLength = (int)NumberConverter.ToUInt24(buffer, offset + ProtocolFormatConst.HandshakeLengthOffset);

            int messageOffset = offset + ProtocolFormatConst.HandshakeHeaderLength;
            
            Handshake parsedHandshake = null;

            switch (handshakeType)
            {
                case HandshakeType.HelloRequest:
                    parsedHandshake = GetHelloRequest(buffer, messageOffset);
                    break;
                case HandshakeType.ClientHello:
                    parsedHandshake = BuildClientHello(buffer, messageOffset, handshakeContentLength);
                    break;
                case HandshakeType.ServerHello:
                    break;
                case HandshakeType.Certificate:
                    break;
                case HandshakeType.ServerKeyExchange:
                    break;
                case HandshakeType.CertificateRequest:
                    break;
                case HandshakeType.ServerHelloDone:
                    break;
                case HandshakeType.CertificateVerify:
                    break;
                case HandshakeType.ClientKeyExchange:
                    break;
                case HandshakeType.Finished:
                    break;
            }

            parsedHandshake.Length = handshakeContentLength;

            return parsedHandshake;
        }

        public int GetHandshakeStructLength(byte[] buffer, int offset)
        {
            int handshakeContentLength = (int)NumberConverter.ToUInt24(buffer, offset + ProtocolFormatConst.HandshakeLengthOffset);
            int headerLength = ProtocolFormatConst.HandshakeHeaderLength;

            return handshakeContentLength + headerLength;
        }

        private Handshake BuildClientHello(byte[] buffer, int messageOffset, int handshakeContentLength)
        {
            ClientHelloBuilder chBuilher = new ClientHelloBuilder();

            return chBuilher.BuildClientHello(buffer, messageOffset, handshakeContentLength);
        }

        private Handshake GetHelloRequest(byte[] buffer, int messageOffset)
        {            

            throw new NotImplementedException();
        }

        ///<summary>Read message length from Handshake header bytes. Buffer length must be at least <see cref="ProtocolFormatConst.HandshakeHeaderLength"/></summary>
        ///<param name="buffer">Buffer contains raw bytes of undetermined <see cref="Handshake"/> message</param>
        ///<param name="offset">Handshake message start</param>
        public int GetLengthFromHeader(byte[] buffer, int offset)
        {
            return (int)NumberConverter.ToUInt24(buffer, offset + ProtocolFormatConst.HandshakeLengthOffset);
        }

        private void ThrowUnrecognizedHandshakeTypeException(byte value)
        {
            string msg = "Unrecognized 'Handshake Type'. {0} is not associate with any 'HandshakeType' enum.";
            throw new MessageFromatException(msg);
        }

        private HandshakeType ParseHandshakeType(byte[] buffer, int offset)
        {
            byte type = buffer[offset];

            if (!Enum.IsDefined(typeof(HandshakeType), type)) ThrowUnrecognizedHandshakeTypeException(type);

            return (HandshakeType)type;

        }
    }
}
