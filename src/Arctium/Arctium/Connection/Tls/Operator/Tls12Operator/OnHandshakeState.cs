using System;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using Arctium.Connection.Tls.Buffers;
using Arctium.Connection.Tls.Protocol.BinaryOps.FixedOps;
using Arctium.Connection.Tls.Protocol.BinaryOps.Builder;
using Arctium.Connection.Tls.Protocol.FormatConsts;
using Arctium.Connection.Tls.Protocol.BinaryOps.Formatter;
using System.Collections.Generic;
using Arctium.Connection.Tls.Protocol.RecordProtocol;

namespace Arctium.Connection.Tls.Operator.Tls12Operator
{
    class OnHandshakeState
    {
        RecordLayer12 recordLayer;
        ChunkedDataBuffer buffer;
        HandshakeBuilder builder;

        List<byte[]> fragmentsExchangeStack;

        public OnHandshakeState(RecordLayer12 recordLayer)
        {
            this.recordLayer = recordLayer;
            buffer = new ChunkedDataBuffer();
            builder = new HandshakeBuilder();
            fragmentsExchangeStack = new List<byte[]>();
        }



        //
        // end callbacks from FramgentReader
        //

        public Handshake Read()
        {
            LoadMessageToBuffer();

            int msgLength = FixedHandshakeInfo.Length(buffer.DataBuffer, buffer.DataOffset);

            Handshake msgObject = builder.GetHandshake(buffer.DataBuffer, buffer.DataOffset);

            buffer.Remove(msgLength);

            return msgObject;
        }

        public void Write(Handshake message)
        {
            HandshakeFormatter formatter = new HandshakeFormatter();

            byte[] fragmentBytes = formatter.GetBytes(message);
            fragmentsExchangeStack.Add(fragmentBytes);
        }

        private void LoadMessageToBuffer()
        {
            while (buffer.DataLength < HandshakeConst.HeaderLength)
            {
                LoadHandshakeFragment();
            }

            int msgLength = FixedHandshakeInfo.Length(buffer.DataBuffer, buffer.DataOffset);

            while (msgLength > buffer.DataLength - HandshakeConst.HeaderLength)
            {
                LoadHandshakeFragment();
            }
        }

        private void LoadHandshakeFragment()
        {
            ContentType type;
            FragmentData data = recordLayer.ReadFragment(out type);

            if (type != ContentType.Handshake) throw new Exception("invalid fragment");

            buffer.PrepareToAppend(data.Length);
            data.Copy(buffer.DataBuffer, buffer.DataOffset + buffer.DataLength);

            buffer.DataLength += data.Length;

            byte[] rawBytes = new byte[data.Length];
            data.Copy(rawBytes, 0);

            fragmentsExchangeStack.Add(rawBytes);
        }
    }
}
