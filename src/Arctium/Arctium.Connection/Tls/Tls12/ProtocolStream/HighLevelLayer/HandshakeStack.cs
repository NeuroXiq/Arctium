using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Connection.Tls.ProtocolStream.HighLevelLayer
{
    ///<summary>
    ///Holds *all* handshake messages bytes (include handshake header bytes with length etc.)
    ///sended and received with holding the order of sending and receiving
    ///</summary>
    class HandshakeStack
    {
        public enum TransmitType
        {
            Sended,
            Received
        };

        public struct HandshakeEntry
        {
            public TransmitType Transmit;
            public HandshakeType HandshakeMsgType;
            public byte[] TransmittedBytes;
        }

        List<HandshakeEntry> stack;
        int sequeneNumber;

        public HandshakeStack()
        {
            stack = new List<HandshakeEntry>();
        }

        public void Push(byte[] bytes, HandshakeType msgType, TransmitType transmitType)
        {
            HandshakeEntry newMsg = new HandshakeEntry();
            newMsg.HandshakeMsgType = msgType;
            newMsg.Transmit = transmitType;
            newMsg.TransmittedBytes = bytes;

            stack.Add(newMsg);
        }

        public HandshakeEntry[] GetStack()
        {
            return stack.ToArray();
        }

    }
}
