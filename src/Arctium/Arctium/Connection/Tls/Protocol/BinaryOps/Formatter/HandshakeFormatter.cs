using System;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using Arctium.Connection.Tls.Protocol.FormatConsts;
using Arctium.Connection.Tls.Protocol.BinaryOps.Formatter.HandshakeFormatters;
using System.Collections.Generic;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Formatter
{
    ///<summary>Handshake formatter changes object representation of the handshake message to Handshake struct bytes ready to send in record layer fragment</summary>
    class HandshakeFormatter
    {
        static Dictionary<HandshakeType, HandshakeFormatterBase> allFormatters;

        static HandshakeFormatter()
        {
            allFormatters = new Dictionary<HandshakeType, HandshakeFormatterBase>();

            allFormatters[HandshakeType.ClientHello] = new ClientHelloFormatter();

            allFormatters[HandshakeType.ServerHello] = new ServerHelloFormatter();
            allFormatters[HandshakeType.Certificate] = new CertificateFormatter();
            allFormatters[HandshakeType.ServerKeyExchange] = new ServerKeyExchangeFormatter();
            allFormatters[HandshakeType.CertificateRequest] = new CertificateRequestFormatter();
            allFormatters[HandshakeType.ServerHelloDone] = new ServerHelloDoneFormatter();

            allFormatters[HandshakeType.ClientKeyExchange] = new ClientKeyExchangeFormatter();
            allFormatters[HandshakeType.CertificateVerify] = new CertificateVerifyFormatter();
            allFormatters[HandshakeType.Finished] = new FinishedFormatter();
        }

        static HandshakeFormatterBase GetFormatter(HandshakeType type)
        {
            return allFormatters[type];
        }


        public HandshakeFormatter()
        {
        }


        ///<summary>
        ///Creates byte representation of <see cref="Handshake"/> object.
        ///This method creates ready to send  Handshake structure including msg_type and length fields
        ///</summary>
        public int GetBytes(byte[] buffer, int offset, Handshake handshakeMessage)
        {
            HandshakeFormatterBase formatter = GetFormatter(handshakeMessage.MsgType);

            int innerBytesLength = formatter.GetBytes(buffer, offset + 4, handshakeMessage);

            buffer[offset] = (byte)handshakeMessage.MsgType;
            NumberConverter.FormatUInt24(innerBytesLength, buffer, offset + 1);

            return 4 + innerBytesLength;
        }

        public byte[] GetBytes(Handshake handshakeMessage)
        {
            HandshakeFormatterBase formatter = GetFormatter(handshakeMessage.MsgType);
            byte[] buffer = new byte[formatter.GetLength(handshakeMessage) + 4];

            GetBytes(buffer, 0, handshakeMessage);

            return buffer;
        }

        public int GetLength(Handshake handshakeMessage)
        {
            // 1 byte    |3 bytes    | 'handshakeMessage' depend length
            // [msg_type][msg_length][handshake message bytes of msg_type type]
            //                       |
            // this fields           | formatter compute this length
            // formatted do not      |
            // include, they are     |
            // const   of 4 bytes len|

            var formatter = GetFormatter(handshakeMessage.MsgType);

            int msgTypeLength = 1;
            int lengthLength = 3;
            int formattedLength = formatter.GetLength(handshakeMessage);

            return msgTypeLength + lengthLength + formattedLength;
        }
    }
}
