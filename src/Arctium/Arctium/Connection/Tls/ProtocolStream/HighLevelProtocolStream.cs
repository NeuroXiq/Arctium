using Arctium.Connection.Tls.Protocol;
using Arctium.Connection.Tls.Protocol.BinaryOps.Builder;
using Arctium.Connection.Tls.Protocol.BinaryOps.Formatter;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using Arctium.Connection.Tls.Protocol.RecordProtocol;
using Arctium.Connection.Tls.Buffers;
using System;
using Arctium.Connection.Tls.Protocol.FormatConsts;
using Arctium.Connection.Tls.Protocol.BinaryOps.FixedOps;

namespace Arctium.Connection.Tls.ProtocolStream
{
    class HighLevelProtocolStream
    {

        RecordLayer recordLayer;
        HandshakeBuilder handshakeBuilder;
        BufferCache bufferCache;
        ContentType currentContentInCache;

        public HighLevelProtocolStream(RecordLayer recordLayer)
        {
            this.recordLayer = recordLayer;
            handshakeBuilder = new HandshakeBuilder();

            bufferCache = new BufferCache(ProtocolFormatConst.HandshakeMaxLength + ProtocolFormatConst.MaxRecordLength);
        }

        public object Read(out ContentType type)
        {
            if(bufferCache.DataLength == 0)
            {
                ContentType msgType;
                byte[] temp = new byte[128];
                int readed = recordLayer.Read(temp, 0, 128, out msgType);
                bufferCache.WriteFrom(temp, 0, readed);
                currentContentInCache = msgType;
            }

            return LoadFromCache(out type);



            //object parsedObject = null;
            //int protocolStructLength = -1;
            //
            //byte[] tempBuffer = new byte[1024];
            //ContentType contentType;
            //int readedBytes = recordLayer.Read(tempBuffer, 0, 1024, out contentType);
            //
            //bufferCache.TrimStart(protocolStructLength);
        }

        private object LoadFromCache(out ContentType type)
        {
            type = currentContentInCache;
            switch (currentContentInCache)
            {
                case ContentType.ChangeCipherSpec:
                    throw new NotImplementedException();
                    break;
                case ContentType.Alert:
                    throw new NotImplementedException();
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

        private object LoadHandshakeFromCache()
        {
            byte[] temp = new byte[1024];
            ContentType ctype;
            int readed = 0;
            while (bufferCache.DataLength < HandshakeConst.LengthOffset)
            {
                readed += recordLayer.Read(temp, 0, 1024, out ctype);
                if (ctype != ContentType.Handshake) throw new Exception("Invalid order of record layer messages.");
            }

            bufferCache.WriteFrom(temp, 0, readed);
            int bodyLength = FixedHandshakeInfo.Length(bufferCache.Buffer, 0);

            while (bufferCache.DataLength - HandshakeConst.HeaderLength < bodyLength)
            {
                readed = recordLayer.Read(temp, 0, 1024, out ctype);
                if (ctype != ContentType.Handshake) throw new Exception("Invalid order of record layer messages.");

                bufferCache.WriteFrom(temp, 0, readed);
            }

            object parsedObj = handshakeBuilder.GetHandshake(bufferCache.Buffer, 0);

            int totalHandshakeLen = bodyLength + HandshakeConst.HeaderLength;
            bufferCache.TrimStart(totalHandshakeLen);

            return parsedObj;
        }

        private void FillBufferCacheAsHandshake(byte[] tempBuffer, int readedBytes)
        {
            throw new NotImplementedException();
        }

        public void Write(Handshake handshakeMessage)
        {
            HandshakeFormatter handshakeFormatter = new HandshakeFormatter();

            int len = handshakeFormatter.GetLength(handshakeMessage);
            byte[] buf = new byte[len];
            handshakeFormatter.GetBytes(handshakeMessage, buf, 0);
            recordLayer.Write(buf,0,buf.Length, ContentType.Handshake);
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

    }
}
