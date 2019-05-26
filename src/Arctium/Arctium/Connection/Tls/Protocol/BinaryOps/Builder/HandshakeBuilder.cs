using System;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using Arctium.Connection.Tls.Protocol.FormatConsts;
using Arctium.Connection.Tls.Protocol.BinaryOps.Builder.HandshakeBuilders;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Builder
{
    class HandshakeBuilder
    {
        public HandshakeBuilder() { }

        ServerHelloBuilder serverHelloBuilder = new ServerHelloBuilder();
        CertificateBuilder certificateBuilder = new CertificateBuilder();


        public Handshake GetHandshake(byte[] buffer, int offset)
        {
            HandshakeType handshakeType = GetHandshakeType(buffer, offset + ProtocolFormatConst.HandshakeTypeOffset);

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
                    parsedHandshake = serverHelloBuilder.BuildFromBytes(buffer, messageOffset, handshakeContentLength);
                    break;
                case HandshakeType.Certificate:
                    parsedHandshake = certificateBuilder.BuildFromBytes(buffer, messageOffset, handshakeContentLength);
                    break;
                case HandshakeType.ServerKeyExchange:
                    throw new NotImplementedException();
                    break;
                case HandshakeType.CertificateRequest:
                    throw new NotImplementedException();
                    break;
                case HandshakeType.ServerHelloDone:
                    return new ServerHelloDone();
                    break;
                case HandshakeType.CertificateVerify:
                    throw new NotImplementedException();
                    break;
                case HandshakeType.ClientKeyExchange:
                    parsedHandshake = GetClientKeyExchange(buffer, messageOffset, handshakeContentLength);
                    break;
                case HandshakeType.Finished:
                    parsedHandshake = GetFinished(buffer, messageOffset, handshakeContentLength);
                    break;
            }

            //parsedHandshake.Length = handshakeContentLength;
            parsedHandshake.MsgType = handshakeType;
            
            

            return parsedHandshake;
        }

        private Handshake GetFinished(byte[] buffer, int messageOffset, int handshakeContentLength)
        {
            //if (handshakeContentLength != 12) throw new MessageFromatException("Finished Handshake: Content length mu be equal to 12 but current value is: " + handshakeContentLength);

            byte[] verifyData = new byte[handshakeContentLength];
            Buffer.BlockCopy(buffer, messageOffset, verifyData, 0, handshakeContentLength);

            Finished finished = new Finished(verifyData);

            return finished;
        }

        private ClientKeyExchange GetClientKeyExchange(byte[] buffer, int messageOffset, int handshakeContentLength)
        {
            ClientKeyExchange keyExchange = new ClientKeyExchange();
            keyExchange.MsgType = HandshakeType.ClientKeyExchange;
            int encryptedBytesVectorLength = NumberConverter.ToUInt16(buffer, messageOffset);

            int delta = encryptedBytesVectorLength - handshakeContentLength + 2;
            if (delta != 0)
            {
                if (delta > 0) throw new MessageFromatException("Invalid length of vector of ClientKeyExchange encrypted data. Vector is larger than content length");
                else throw new MessageFromatException("Invalid length of vector of ClientKeyExchange encrypted data. Vector is smaller than content length");
            }

            int encryptedBytesOffset = messageOffset + 2;

            keyExchange.ExchangeKeys = new byte[encryptedBytesVectorLength];
            Array.Copy(buffer, encryptedBytesOffset, keyExchange.ExchangeKeys, 0, encryptedBytesVectorLength);

            return keyExchange;
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
