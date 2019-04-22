using System;
using Arctium.Connection.Tls.HandshakeProtocol;
using Arctium.Connection.Tls.Protocol;

namespace Arctium.Connection.Tls.BinaryOps.Parser
{
    class HandshakeParser
    {
        public HandshakeParser() { }


        public Handshake GetHandshake(byte[] buffer, int offset)
        {
            HandshakeType handshakeType = ParseHandshakeType(buffer, offset + ProtocolFromatConst.HandshakeTypeOffset);
            int length = ParseLength(buffer, offset + ProtocolFromatConst.HandshakeLengthOffset);

            int messageOffset = offset + ProtocolFromatConst.HandshakeHeaderLength;
            Handshake parsedHandshake = null;

            switch (handshakeType)
            {
                case HandshakeType.HelloRequest:
                    parsedHandshake = GetHelloRequest(buffer, messageOffset);
                    break;
                case HandshakeType.ClientHello:
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

            return parsedHandshake;
        }

        private Handshake GetHelloRequest(byte[] buffer, int messageOffset)
        {
            throw new NotImplementedException();
        }

        ///<summary>Read message length from Handshake header bytes. Buffer length must be at least <see cref="ProtocolFromatConst.HandshakeHeaderLength"/></summary>
        ///<param name="buffer">Buffer contains raw bytes of undetermined <see cref="Handshake"/> message</param>
        ///<param name="offset">Handshake message start</param>
        public int GetLengthFromHeader(byte[] buffer, int offset)
        {
            return ParseLength(buffer, offset);
        }

        private void ThrowUnrecognizedHandshakeTypeException(byte value)
        {
            string msg = "Unrecognized 'Handshake Type'. {0} is not associate with any 'HandshakeType' enum.";
            throw new MessageFromatException(msg);
        }

        private int ParseLength(byte[] buffer, int offset)
        {
            // Explicit convertion from bytes to length.
            // Big-endian manner

            byte b1 = buffer[offset + 0]; 
            byte b2 = buffer[offset + 1]; 
            byte b3 = buffer[offset + 2];

            
            int length = (b1 << 0) | (b2 << 8) | (b3 << 16);

            return length;
        }

        private HandshakeType ParseHandshakeType(byte[] buffer, int offset)
        {
            byte type = buffer[offset];

            if (!Enum.IsDefined(typeof(HandshakeType), type)) ThrowUnrecognizedHandshakeTypeException(type);

            return (HandshakeType)type;

        }
    }
}
