using Arctium.Connection.Tls.Protocol;
using Arctium.Connection.Tls.Protocol.BinaryOps.Builder;
using Arctium.Connection.Tls.Protocol.BinaryOps.Formatter;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using Arctium.Connection.Tls.Protocol.RecordProtocol;
using Arctium.Connection.Tls.Buffers;
using System;
using Arctium.Connection.Tls.Protocol.FormatConsts;
using Arctium.Connection.Tls.Protocol.BinaryOps.FixedOps;
using Arctium.Connection.Tls.Protocol.ChangeCipherSpecProtocol;
using Arctium.Connection.Tls.Protocol.AlertProtocol;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer11;

namespace Arctium.Connection.Tls.ProtocolStream.HighLevelLayer
{
    class HighLevelProtocolStream
    {
        RecordLayer11 recordLayer;
        HandshakeBuilder handshakeBuilder;
        BufferCache bufferCache;
        ContentType currentContentInCache;
        HandshakeFormatter handshakeFormatter;

        public HighLevelProtocolStream(RecordLayer11 recordLayer)
        {
            this.recordLayer = recordLayer;
            handshakeBuilder = new HandshakeBuilder();
            handshakeFormatter = new HandshakeFormatter();

            bufferCache = new BufferCache(ProtocolFormatConst.HandshakeMaxLength + ProtocolFormatConst.MaxRecordLength);
        }

        public void UpdateRecordLayer(SecParams11 secParams)
        {
            recordLayer.ChangeCipherSpec(secParams);
        }


        //
        //Read methods
        //


        public object Read(out ContentType type)
        {
            if (bufferCache.DataLength == 0)
            {
                ContentType msgType;
                byte[] temp = new byte[2 << 14 + 2048];
                msgType = recordLayer.LoadFragment().ContentType;
                int readed = recordLayer.Read(temp, 0).Length;

                bufferCache.WriteFrom(temp, 0, readed);
                currentContentInCache = msgType;
            }

            return LoadFromCache(out type);

        }

        private object LoadFromCache(out ContentType type)
        {
            type = currentContentInCache;
            switch (currentContentInCache)
            {
                case ContentType.ChangeCipherSpec:
                    return ReadChangeCipherSpecFromCache();
                    break;
                case ContentType.Alert:
                    return LoadAlertFromCache();
                    break;
                case ContentType.Handshake:
                    return LoadHandshakeFromCache();
                    break;
                case ContentType.ApplicationData:
                    throw new NotImplementedException();
                    break;
                default:
                    throw new NotImplementedException();
                    break;
            }
        }

        private object LoadAlertFromCache()
        {
            
            AlertBuilder ab = new AlertBuilder();

            var a = new Alert();
            a.Level = (AlertLevel)bufferCache.Buffer[0];
            a.Description = (AlertDescription)bufferCache.Buffer[1];
            bufferCache.TrimStart(2);
            return a;
        }

        private object ReadChangeCipherSpecFromCache()
        {
            if (bufferCache.DataLength == 1)
            {
                if (bufferCache.Buffer[0] == 1)
                {
                    ChangeCipherSpec ccs = new ChangeCipherSpec();
                    ccs.CCSType = ChangeCipherSpecType.ChangeCipherSpec;

                    bufferCache.TrimStart(1);

                    return ccs;
                }
                else throw new Exception("chagne cipher spec invalid type");
            }
            else throw new Exception("Invalid change cipher spec in cache");
        }

        private object LoadHandshakeFromCache()
        {
            byte[] temp = new byte[2 << 14 + 2048];
            ContentType ctype;
            int readed = 0;
            while (bufferCache.DataLength < HandshakeConst.LengthOffset)
            {
                ctype = recordLayer.LoadFragment().ContentType;
                readed += recordLayer.Read(temp, 0).Length;
                if (ctype != ContentType.Handshake) throw new Exception("Invalid order of record layer messages.");
            }

            bufferCache.WriteFrom(temp, 0, readed);
            int bodyLength = FixedHandshakeInfo.Length(bufferCache.Buffer, 0);

            while (bufferCache.DataLength - HandshakeConst.HeaderLength < bodyLength)
            {
                ctype = recordLayer.LoadFragment().ContentType;
                readed = recordLayer.Read(temp, 0).Length;
                if (ctype != ContentType.Handshake) throw new Exception("Invalid order of record layer messages.");

                bufferCache.WriteFrom(temp, 0, readed);
            }


            int totalHandshakeLen = bodyLength + HandshakeConst.HeaderLength;
            object parsedObj = handshakeBuilder.GetHandshake(bufferCache.Buffer, 0);



            bufferCache.TrimStart(totalHandshakeLen);

            return parsedObj;
        }

        //
        // Write methods
        //

        public void Write(Finished finished)
        {
            byte[] handshakedBytes = handshakeFormatter.GetBytes(finished);

            recordLayer.Write(handshakedBytes, 0, handshakedBytes.Length, ContentType.Handshake);
        }

        public void Write(ChangeCipherSpec ccs)
        {
            byte[] changeCsBytes = new byte[1];
            changeCsBytes[0] = (byte)ccs.CCSType;

            recordLayer.Write(changeCsBytes, 0, 1, ContentType.ChangeCipherSpec);
        }

        public void Write(ServerHello handshakeMessage)
        {
            byte[] handshakeBytes = handshakeFormatter.GetBytes(handshakeMessage);

            recordLayer.Write(handshakeBytes, 0, handshakeBytes.Length, ContentType.Handshake);
        }

        public void Write(Certificate certificate)
        {
            byte[] handshakebytes = handshakeFormatter.GetBytes(certificate);
            recordLayer.Write(handshakebytes, 0, handshakebytes.Length, ContentType.Handshake);
        }

        public void Write(ServerHelloDone serverHelloDone)
        {
            byte[] handshakeBytes = handshakeFormatter.GetBytes(serverHelloDone);
            recordLayer.Write(handshakeBytes, 0, handshakeBytes.Length, ContentType.Handshake);
        }
    }
}


//private ContentType CompactFragmentsToCache()
//{
//    byte[] tempBuf = new byte[1];



//    bufferCache.WriteFrom(recordLayer.Fragment, 0, recordLayer.Length);

//    switch (recordLayer.Type)
//    {
//        case ContentType.ChangeCipherSpec:
//            break;
//        case ContentType.Alert:
//            break;
//        case ContentType.Handshake:
//            FillBufferAsHandshake();
//            break;
//        case ContentType.ApplicationData:
//            break;
//        default:
//            break;
//    }

//    return recordLayer.Type;
//}

//private void FillBufferAsHandshake()
//{
//    while (bufferCache.DataLength < ProtocolFormatConst.HandshakeHeaderLength)
//    {
//        WriteHandshakeToBufferCache();
//    }

//    int expectedContentLength = handshakeBuilder.GetLengthFromHeader(bufferCache.Buffer, 0);

//    while (bufferCache.DataLength - ProtocolFormatConst.HandshakeHeaderLength < expectedContentLength)
//    {
//        WriteHandshakeToBufferCache();
//    }
//}

//private void WriteHandshakeToBufferCache()
//{
//    TlsPlainText record = recordLayer.Read();
//    if (record.Type != ContentType.Handshake) throw new Exception("Invalid record type, expected handshake content type");
//    bufferCache.WriteFrom(record.Fragment, 0, record.Length);
//}