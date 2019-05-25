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
using Arctium.Connection.Tls.Protocol.AlertProtocol;
using Arctium.Connection.Tls.Exceptions;

namespace Arctium.Connection.Tls.Operator.Tls12Operator
{
    class HandshakeIO
    {
        public struct HandshakeMessageData
        {
            public byte[] RawBytes;
            public HandshakeType Type;

            public HandshakeMessageData(byte[] rawBytes, HandshakeType type)
            {
                RawBytes = rawBytes;
                Type = type;
            }
        }

        ///<summary>Gets *all* sended and received bytes of the handshake messages. Order in the array matches order of the read/write operations</summary>
        ///<remarks>Cache contains all messages, also this messages  which should not be included in Finished message calculations</remarks>
        public HandshakeMessageData[] HandshakeTransmissionCache { get { return messagesTransmissionCache.ToArray(); } }

        RecordLayer12 recordLayer;
        ChunkedDataBuffer buffer;
        HandshakeBuilder builder;

        List<HandshakeMessageData> messagesTransmissionCache;

        byte[] readBuffer = new byte[0x48 + 2048];

        public HandshakeIO(RecordLayer12 recordLayer)
        {
            this.recordLayer = recordLayer;
            buffer = new ChunkedDataBuffer();
            builder = new HandshakeBuilder();
            messagesTransmissionCache = new List<HandshakeMessageData>();

        }

        public Handshake Read()
        {
            LoadMessageToBuffer();

            int contentLength = FixedHandshakeInfo.Length(buffer.DataBuffer, buffer.DataOffset);
            int totalLength = contentLength + HandshakeConst.HeaderLength;

            Handshake msgObject = builder.GetHandshake(buffer.DataBuffer, buffer.DataOffset);

            byte[] rawFragment = new byte[totalLength];
            Buffer.BlockCopy(buffer.DataBuffer, buffer.DataOffset, rawFragment, 0, totalLength);
            messagesTransmissionCache.Add(new HandshakeMessageData(rawFragment, msgObject.MsgType));

            buffer.Remove(totalLength);

            return msgObject;
        }

        public void Write(Handshake message)
        {
            HandshakeFormatter formatter = new HandshakeFormatter();

            byte[] fragmentBytes = formatter.GetBytes(message);
            messagesTransmissionCache.Add(new HandshakeMessageData(fragmentBytes, message.MsgType));
            recordLayer.Write(fragmentBytes, 0, fragmentBytes.Length, ContentType.Handshake);
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
            int readed = recordLayer.ReadFragment(readBuffer, 0, out type);

            if (type != ContentType.Handshake)
            {
                if (type == ContentType.Alert)
                {
                    Alert receivedAlert = AlertBuilder.FromBytes(readBuffer, 0, readed);
                    ThrowReceivedAlertException(receivedAlert);
                }
                throw new FatalAlertException("HandshakeIO","On reading handshake",(int)(AlertDescription.UnexpectedMessage) ,"Received unrecognized fragment instead of handshake fragment");
            }

            buffer.Append(readBuffer, 0, readed);
        }

        private void ThrowReceivedAlertException(Alert alert)
        {
            int num = (int)alert.Description;
            string where = "HandshakIO";
            string when = "On reading handshake message";
            string description = "Expected to read handshake message but received alert";

            if (alert.Level == AlertLevel.Warning)
                throw new ReceivedWarningAlertException(num, when, where, description);
            else if (alert.Level == AlertLevel.Fatal) throw new ReceivedFatalAlertException(num, where, when, description);

            throw new Exception("Internal error unhandler alert exception in HandshakeIO, unrecognized alert");
        }
    }
}
