using Arctium.Protocol.Tls.Protocol;
using Arctium.Protocol.Tls.Protocol.BinaryOps.Builder;
using Arctium.Protocol.Tls.Protocol.BinaryOps.Formatter;
using Arctium.Protocol.Tls.Protocol.HandshakeProtocol;
using Arctium.Protocol.Tls.Protocol.RecordProtocol;
using Arctium.Protocol.Tls.Tls12.Buffers;
using System;
using Arctium.Protocol.Tls.Protocol.Consts;
using Arctium.Protocol.Tls.Protocol.BinaryOps.FixedOps;
using Arctium.Protocol.Tls.Protocol.ChangeCipherSpecProtocol;
using Arctium.Protocol.Tls.Protocol.AlertProtocol;
using Arctium.Protocol.Tls.ProtocolStream.RecordsLayer.RecordsLayer11;
using Arctium.Protocol.Tls.Tls12.CryptoConfiguration;
using Arctium.Protocol.Tls.Protocol.BinaryOps.Builder.HandshakeBuilders;

namespace Arctium.Protocol.Tls.ProtocolStream.HighLevelLayer
{
    class HighLevelProtocolStream
    {
        RecordLayer11 recordLayer;
        HandshakeBuilder handshakeBuilder;
        BufferCache bufferCache;
        ContentType currentContentInCache;
        HandshakeFormatter handshakeFormatter;


        public delegate void ReadedHandshakeCallback(Handshake message, byte[] rawBytes);
        public delegate void ReadedChangecipherSpecCallback(ChangeCipherSpec changeCipherSpec);
        public delegate void ReadedAlertCallback(Alert alert);
        public delegate void ReadedApplicationDataCallback(byte[] buffer, int offset, int length);

        public event ReadedHandshakeCallback HandshakeHandler;
        public event ReadedChangecipherSpecCallback ChangeCipherSpecHandler;
        public event ReadedAlertCallback AlertHandler;
        public event ReadedApplicationDataCallback ApplicationDataHandler;


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


        public void Read()
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
            LoadFromCache();
        }

        private void LoadFromCache()
        {
            
            switch (currentContentInCache)
            {
                case ContentType.ChangeCipherSpec:
                    ReadChangeCipherSpecFromCache();
                    break;
                case ContentType.Alert:
                    LoadAlertFromCache();
                    break;
                case ContentType.Handshake:
                    LoadHandshakeFromCache();
                    break;
                case ContentType.ApplicationData:
                    ApplicationDataHandler?.Invoke(bufferCache.Buffer, 0, bufferCache.DataLength);
                    bufferCache.TrimStart(bufferCache.DataLength);
                    break;
                default:
#pragma warning disable
                    throw new NotImplementedException();
                    break;
            }
        }

        private void LoadAlertFromCache()
        {
            
            AlertBuilder ab = new AlertBuilder();

            var a = new Alert((AlertLevel)bufferCache.Buffer[0], (AlertDescription)bufferCache.Buffer[1]);

            AlertHandler?.Invoke(a);

            bufferCache.TrimStart(2);
            //return a;
        }

        private void ReadChangeCipherSpecFromCache()
        {
            if (bufferCache.DataLength == 1)
            {
                if (bufferCache.Buffer[0] == 1)
                {
                    ChangeCipherSpec ccs = new ChangeCipherSpec();
                    ccs.CCSType = ChangeCipherSpecType.ChangeCipherSpec;

                    ChangeCipherSpecHandler?.Invoke(ccs);

                    bufferCache.TrimStart(1);

                    
                }
                else throw new Exception("chagne cipher spec invalid type");
            }
            else throw new Exception("Invalid change cipher spec in cache");
        }

        private void LoadHandshakeFromCache()
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
            Handshake parsedObj = handshakeBuilder.GetHandshake(bufferCache.Buffer, 0);
            byte[] rawBytes = new byte[totalHandshakeLen];

            Buffer.BlockCopy(bufferCache.Buffer, 0, rawBytes, 0, totalHandshakeLen);

            HandshakeHandler?.Invoke(parsedObj, rawBytes);

            bufferCache.TrimStart(totalHandshakeLen);
        }

        //
        // Write methods
        //

        public void WriteApplicationData(byte[] buffer, int offset, int count)
        {
            recordLayer.Write(buffer, offset, count, ContentType.ApplicationData);
        }

        public void Write(Handshake handshakeMessage)
        {
            byte[] bytes = handshakeFormatter.GetBytes(handshakeMessage);
            recordLayer.Write(bytes, 0, bytes.Length, ContentType.Handshake);
        }
     
        public void Write(ChangeCipherSpec ccs)
        {
            byte[] changeCsBytes = new byte[1];
            changeCsBytes[0] = (byte)ccs.CCSType;

            recordLayer.Write(changeCsBytes, 0, 1, ContentType.ChangeCipherSpec);
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