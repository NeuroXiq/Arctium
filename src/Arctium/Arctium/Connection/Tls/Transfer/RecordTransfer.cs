using Arctium.Connection.Tls.RecordProtocol;
using System.IO;
using Arctium.Connection.Tls.BinaryOps.Parser;
using Arctium.Connection.Tls.Protocol;
using Arctium.Connection.Tls.BinaryOps;

namespace Arctium.Connection.Tls.Transfer
{
    class RecordTransfer
    {

        Stream innerStream;
        BufferCache bufferCache;
        RecordParser recordParser;

        public RecordTransfer(Stream innerStream)
        {
            this.innerStream = innerStream;
            bufferCache = new BufferCache(ProtocolFromatConst.MaxRecordLength);
            recordParser = new RecordParser();
        }


        //TODO ignore unrecognized types
        public Record Read()
        {
            EnsureAtLeastOneRecord();
            int recordLength = GetExpectedRecordLength();

            Record parsedRecord = recordParser.GetRecord(bufferCache.Buffer, 0, recordLength);

            //remove parsed bytes from buffer cache
            bufferCache.TrimStart(recordLength);

            return parsedRecord;
        }

        private void EnsureAtLeastOneRecord()
        {
            while (!ContainsRecordBytes())
            {
                int readed = bufferCache.WriteFrom(innerStream);

                if (readed == 0)
                {
                    throw new RecordTransferException("Unable to read record bytes from stream." + 
                                                      " Stream returns 0 bytes or record bytes count exceed maximum limit");
                }
            }
        }

        ///<summary>Indicates if current <see cref="bufferCache"/> contains all bytes of at least one record</summary>
        private bool ContainsRecordBytes()
        {
            if (bufferCache.DataLength >= ProtocolFromatConst.RecordHeaderLength)
            {
                int expectedRecordLength = GetExpectedRecordLength();

                bool bufferHaveMinimumDataLength = expectedRecordLength <= bufferCache.DataLength;

                return bufferHaveMinimumDataLength;
            }
            else return false;
        }
        
        private int GetExpectedRecordLength()
        {
            byte[] buffer = bufferCache.Buffer;

            //endianness problems, do explicity conversion as big-endian
            //ushort expectedLength = BitConverter.ToUInt16(buffer, LengthBytesOffset)

            ushort fragmentLength = NumberConverter.ToUInt16(buffer, ProtocolFromatConst.RecordLengthOffset);

            int recordLength = fragmentLength + ProtocolFromatConst.RecordHeaderLength;

            return recordLength;
        }

        public void Write(Record record)
        {

        }



    }
}
