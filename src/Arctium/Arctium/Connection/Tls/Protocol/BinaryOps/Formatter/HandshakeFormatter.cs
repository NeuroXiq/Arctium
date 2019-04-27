using System;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using Arctium.Connection.Tls.Protocol.FormatConsts;
using Arctium.Connection.Tls.Protocol.BinaryOps.Formatter.HandshakeFormatters;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Formatter
{
    class HandshakeFormatter
    {
        ServerHelloFormater serverHelloFormatter;
        CertificateFormatter certificateFormatter;
        ServerHelloDoneFormatter serverHelloDoneFormatter;

        public HandshakeFormatter()
        {
            serverHelloFormatter = new ServerHelloFormater();
            certificateFormatter = new CertificateFormatter();
            serverHelloDoneFormatter = new ServerHelloDoneFormatter();
        }

        private byte[] FormatHandshake(HandshakeType type, byte[] innerMsgBytes)
        {
            byte[] handshakeBytes = new byte[innerMsgBytes.Length + HandshakeConst.HeaderLength];

            handshakeBytes[0] = (byte)type;
            NumberConverter.FormatUInt24(innerMsgBytes.Length, handshakeBytes, 1);

            int innerMsgOffset = HandshakeConst.HeaderLength;
            Array.Copy(innerMsgBytes, 0, handshakeBytes, innerMsgOffset, innerMsgBytes.Length);

            return handshakeBytes;
        }

        public byte[] GetBytes(ServerHello serverHello)
        {
            byte[] innerMsgBytes =  serverHelloFormatter.GetBytes(serverHello);
            byte[] handshakeBytes = FormatHandshake(HandshakeType.ServerHello, innerMsgBytes);

            return handshakeBytes;
        }

        public byte[] GetBytes(Certificate certificate)
        {
            byte[] innerMsgBytes = certificateFormatter.GetBytes(certificate);
            byte[] handshakeBytes = FormatHandshake(HandshakeType.Certificate, innerMsgBytes);

            return handshakeBytes;
        }

        public byte[] GetBytes(ServerHelloDone serverHelloDone)
        {
            byte[] innerMsgBytes = serverHelloDoneFormatter.GetBytes(serverHelloDone);
            byte[] handshakeBytes = FormatHandshake(HandshakeType.ServerHelloDone, innerMsgBytes);

            return handshakeBytes;
        }
        
    }
}
