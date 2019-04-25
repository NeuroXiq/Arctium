using Arctium.Connection.Tls.Protocol.FormatConsts;
using Arctium.Connection.Tls.Buffers;
using System.IO;
using System;
using Arctium.Connection.Tls.Protocol.BinaryOps.FixedOps;

namespace Arctium.Connection.Tls.ProtocolStream
{
    class RecordReader
    {
        BufferCache bufferCache;
        Stream innerStream;

        public RecordReader(Stream innerStream)
        {
            this.innerStream = innerStream;
            bufferCache = new BufferCache(RecordConst.MaxTlsRecordLength);
        }

        ///<summary>Loads record bytes from innerStream</summary>
        ///<returns>Whole length of record</returns>
        ///<remarks>This method ensures, that one record with entire content is successfully readed from inner stream</remarks>
        public int LoadRecord()
        {
            LoadRecordHeader();
            int contentLength = FixedRecordInfo.FragmentLength(bufferCache.Buffer, 0);
            LoadFragmentBytes(contentLength);

            return contentLength + RecordConst.HeaderLength;
        }

        private void LoadFragmentBytes(int fragmentLength)
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
                    bufferCache.WriteFrom(innerStream);       
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
            return fullLength;
        }

    }
}
