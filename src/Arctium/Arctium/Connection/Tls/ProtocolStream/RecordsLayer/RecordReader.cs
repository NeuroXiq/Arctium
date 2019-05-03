using Arctium.Connection.Tls.Protocol.FormatConsts;
using Arctium.Connection.Tls.Buffers;
using System.IO;
using System;
using Arctium.Connection.Tls.Protocol.BinaryOps.FixedOps;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer
{
    class RecordReader
    {
        BufferCache bufferCache;
        Stream innerStream;

        public ulong SequenceNumber { get
            {
                if (readedRecordsCount == 0)
                    throw new InvalidOperationException("Cannot get Sequence number because any record was not readed yet");
                return readedRecordsCount - 1;
            } }
        private ulong readedRecordsCount;

        public RecordReader(Stream innerStream)
        {
            this.innerStream = innerStream;
            bufferCache = new BufferCache(RecordConst.MaxTlsRecordLength);
            readedRecordsCount = 0;
        }

        ///<summary>Loads record bytes from innerStream</summary>
        ///<returns>Whole length of record</returns>
        ///<remarks>This method ensures, that at least one record with entire content is successfully readed from inner stream</remarks>
        public int LoadRecord()
        {
            LoadRecordHeader();
            int contentLength = FixedRecordInfo.FragmentLength(bufferCache.Buffer, 0);
            LoadRemainingFragmentBytes(contentLength);

            return contentLength + RecordConst.HeaderLength;
        }

        private void LoadRemainingFragmentBytes(int fragmentLength)
        {
            int fullLength = fragmentLength + RecordConst.HeaderLength;

            while (bufferCache.DataLength < fullLength)
            {
                bufferCache.WriteFrom(innerStream);
            }
        }

        private void LoadRecordHeader()
        {
            if (bufferCache.DataLength < RecordConst.LengthOffset + 2)
            {
                while (bufferCache.DataLength < RecordConst.LengthOffset + 2)
                {
                    int readed = bufferCache.WriteFrom(innerStream);
                    if (readed < 1) throw new Exception("innerStream returns 0 bytes after read");
                }
            }
        }

        public int ReadRecord(byte[] buffer, int offset)
        {
            int fullLength = FixedRecordInfo.FragmentLength(bufferCache.Buffer, 0) +  RecordConst.HeaderLength;
            for (int i = 0; i < fullLength; i++)
            {
                buffer[i] = bufferCache.Buffer[i];
            }

            bufferCache.TrimStart(fullLength);
            readedRecordsCount++;

            return fullLength;
        }

    }
}
