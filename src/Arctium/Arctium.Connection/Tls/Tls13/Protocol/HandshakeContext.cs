using Arctium.Connection.Tls.Tls13.Model;
using Arctium.Shared.Exceptions;
using Arctium.Shared.Helpers.Buffers;
using System;
using System.Collections.Generic;

namespace Arctium.Connection.Tls.Tls13.Protocol
{
    internal class HandshakeContext
    {
        public struct MessageInfo
        {
            public int Offset;
            public int Length;
            public int LengthTo;
            public HandshakeType HandshakeType;

            public MessageInfo(HandshakeType type, int offset, int length, int lengthTo)
            {
                HandshakeType = type;
                Offset = offset;
                Length = length;
                LengthTo = lengthTo;
            }
        }

        public byte[] HandshakeMessages { get { return byteBuffer.Buffer; } }
        public int TotalLength { get { return byteBuffer.DataLength; } }
        // public int ClientHelloPskOffset { get; private set; }
        public List<MessageInfo> MessagesInfo { get; private set; }

        public int LengthToPskBinders { get { return FindLengthToPskBinders(); } }

        private int FindLengthToPskBinders()
        {
            int length = -1;
            // if clienthello2 not found then poinst to clienthello1
            int clientHello1or2Offset = -1;

            for (int i = MessagesInfo.Count - 1; i >= 0 && (clientHello1or2Offset == -1); i--)
            {
                if (MessagesInfo[i].HandshakeType == HandshakeType.ClientHello)
                    clientHello1or2Offset = MessagesInfo[i].Offset;
            }

            if (clientHello1or2Offset == -1) throw new ArctiumExceptionInternal();

            int offset = ModelDeserialization.HelperGetOffsetOfPskExtensionInClientHello(HandshakeMessages, clientHello1or2Offset);

            if (offset == -1) throw new ArctiumExceptionInternal();

            return offset;
        }

        private ByteBuffer byteBuffer;

        public HandshakeContext()
        {
            byteBuffer = new ByteBuffer();
            MessagesInfo = new List<MessageInfo>();
        }

        public void Add(HandshakeType type, byte[] buffer, int offset, int length)
        {
            int o = byteBuffer.DataLength;
            byteBuffer.Append(buffer, offset, length);
            MessagesInfo.Add(new MessageInfo(type, o, length, byteBuffer.DataLength));

            // ModelDeserialization.HelperGetOffsetOfPskExtensionInClientHello
        }
    }
}
