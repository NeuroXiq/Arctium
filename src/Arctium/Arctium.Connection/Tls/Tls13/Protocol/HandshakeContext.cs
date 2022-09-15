﻿using Arctium.Connection.Tls.Tls13.Model;
using Arctium.Shared.Exceptions;
using Arctium.Shared.Helpers.Buffers;
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
        public int ClientHelloPskOffset { get; private set; }
        public List<MessageInfo> MessagesInfo { get; private set; }

        private ByteBuffer byteBuffer;

        public HandshakeContext()
        {
            byteBuffer = new ByteBuffer();
            MessagesInfo = new List<MessageInfo>();
            ClientHelloPskOffset = -1;
        }

        public void Add(HandshakeType type, byte[] buffer, int offset, int length)
        {
            int o = byteBuffer.DataLength;
            byteBuffer.Append(buffer, offset, length);
            MessagesInfo.Add(new MessageInfo(type, o, length, byteBuffer.DataLength));
        }

        public void SetClientHelloPskExtensionOffset(int clientHelloPskExtensionOffset)
        {
            ClientHelloPskOffset = clientHelloPskExtensionOffset;
        }
    }
}