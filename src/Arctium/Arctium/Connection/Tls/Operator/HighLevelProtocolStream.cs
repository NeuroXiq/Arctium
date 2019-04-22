using Arctium.Connection.Tls.HandshakeProtocol;
using Arctium.Connection.Tls.Protocol;
using Arctium.Connection.Tls.RecordProtocol;
using Arctium.Connection.Tls.Transfer;
using Arctium.Connection.Tls.BinaryOps.Parser;
using System;

namespace Arctium.Connection.Tls.Operator
{
    class HighLevelProtocolStream
    {
        RecordProtocolStream recordStream;
        HandshakeProtocolReader handshakeProtocolReader;
        HandshakeParser handshakeParser;
        BufferCache bufferCache;

        public HighLevelProtocolStream(RecordProtocolStream recordStream)
        {
            this.recordStream = recordStream;
            handshakeParser = new HandshakeParser();
            handshakeProtocolReader = new HandshakeProtocolReader();

            // ??? this size of buffer cache ensure that at least one entire hanshake message fit in it 
            //and leave space to new record with 'some' data. If handshake message wasn't fit in this size,
            //message have in invalid format and this size of Handshake message is not defined by TLS 1.1 standard. 
            bufferCache = new BufferCache(ProtocolFromatConst.HandshakeMaxLength + ProtocolFromatConst.MaxRecordLength);
        }

        ContentType currentContentTypeInBuffer;

        public object Read(out ContentType objectType)
        {
            LoadNextDataToBufferIfNeeded();
            objectType= 0;
            return null;
            object parsedMessage = ParseNextDataFromBuffer(out objectType);
        }

        private object ParseNextDataFromBuffer(out ContentType type)
        {
            type = 0;
            return null;
        }

        private void LoadNextDataToBufferIfNeeded()
        {
            if (bufferCache.DataLength == 0)
            {
                TlsPlainText record = recordStream.Read();
                bufferCache.WriteFrom(record.Fragment, 0, record.Length);
                currentContentTypeInBuffer = record.Type;
            }
            else
            {
                switch (currentContentTypeInBuffer)
                {
                    case ContentType.Alert:
                        break;
                    case ContentType.ApplicationData:
                        break;
                    case ContentType.ChangeCipherSpec:
                        break;
                    case ContentType.Handshake:
                        handshakeProtocolReader.DoMagicThatInBufferBeAtLeastOneHandshakeMessage(bufferCache, recordStream);
                        break;
                }
            }
            
        }

        public Handshake ReadHandshake()
        {
            EnsureOneHandshakeData();
            Handshake handshake = handshakeParser.GetHandshake(bufferCache.Buffer, 0);

            //header length + content length == length of all bytes of current handshake
            int handshakeLength = handshake.Length + ProtocolFromatConst.HandshakeHeaderLength;

            //remove parsed handshake bytes from buffer and shift all remaining to left (reset position)
            bufferCache.TrimStart(handshakeLength);

            return handshake;
        }

        private void EnsureOneHandshakeData()
        {
            if (!ContainsOneHandshake())
            {
                TlsPlainText record = ReadHandshakeRecord();
                int writed = bufferCache.WriteFrom(record.Fragment, 0, record.Length);

                if (writed != record.Length)
                {
                    throw new MessageFromatException("Handshake message length exceed maximum limit.");
                }
            }
        }

        private TlsPlainText ReadHandshakeRecord()
        {
            TlsPlainText record = recordStream.Read();

            if (record.Type == ContentType.Handshake)
            {
                return record;
            }
            else
            {
                throw new InvalidContentTypeException("Invalid type of record (Expected Handshake)", ContentType.Handshake, record);
            }
        }

        ///<summary>Indicates if current <see cref="bufferCache"/> contains bytes of at least one handshake message</summary>
        private bool ContainsOneHandshake()
        {
            //contains at least header bytes ?
            if (bufferCache.DataLength < ProtocolFromatConst.HandshakeHeaderLength) return false;
            byte[] buf = bufferCache.Buffer;

            //parse only few bytes from beginning of buffer to determine length.
            int length = handshakeParser.GetLengthFromHeader(buf, 0);
            
            //readed at least 'length' bytes ?
            bool containsMinimumBytes = bufferCache.DataLength >= length;

            return containsMinimumBytes;
        }
    }
}
