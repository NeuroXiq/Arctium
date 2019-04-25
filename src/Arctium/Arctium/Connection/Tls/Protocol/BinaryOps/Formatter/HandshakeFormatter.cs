using System;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Formatter
{
    class HandshakeFormatter
    {
        const int HandshakeHeaderLength = 4;

        ServerHelloFormater serverHelloFormatter;


        public HandshakeFormatter()
        {
            serverHelloFormatter = new ServerHelloFormater();
        }
        
        public int GetBytes(Handshake handshake, byte[] buffer, int offset)
        {
            int messageFormatOffset = HandshakeHeaderLength + offset;
            int messageLength = -1;
            switch (handshake.MsgType)
            {
                case HandshakeType.HelloRequest:
                    break;
                case HandshakeType.ClientHello:
                    break;
                case HandshakeType.ServerHello:
                    messageLength = FormatServerHello(handshake as ServerHello, buffer, messageFormatOffset);
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
                default:
                    break;
            }

            FormatHandshakeHeader(handshake, buffer, offset);

            return messageLength + HandshakeHeaderLength;
        }

        private void FormatHandshakeHeader(Handshake handshake, byte[] buffer, int offset)
        {
            buffer[offset] = (byte)handshake.MsgType;
            NumberConverter.FormatUInt24((int)handshake.Length, buffer, offset + 1);
        }

        private int FormatServerHello(ServerHello serverHello, byte[] buffer, int offset)
        {
            ServerHelloFormater shf = new ServerHelloFormater();
            return shf.GetBytes(serverHello, buffer, offset);
        }

        public int GetLength(Handshake handshake)
        {
            int messageLength = -1;
            switch (handshake.MsgType)
            {
                case HandshakeType.HelloRequest:
                    break;
                case HandshakeType.ClientHello:
                    break;
                case HandshakeType.ServerHello:
                    messageLength = serverHelloFormatter.GetLength(handshake as ServerHello);
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
                default:
                    break;
            }

            return messageLength + HandshakeHeaderLength;
        }
    }
}
