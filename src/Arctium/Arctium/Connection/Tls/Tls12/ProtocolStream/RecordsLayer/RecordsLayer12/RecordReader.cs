using Arctium.Standards.Connection.Tls.Protocol.RecordProtocol;
using System.IO;
using System;
using Arctium.Standards.Connection.Tls.Protocol.Consts;
using Arctium.Standards.Connection.Tls.Protocol.BinaryOps.FixedOps;

namespace Arctium.Standards.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12
{
    // Optimized record reader
    //


    ///<summary>This class facilitate work with tls records</summary>
    class RecordReader
    {
        public byte[] DataBuffer { get; private set; }

        int dataLength;
        int dataOffset;

        Stream innerStream;
        int maxFragmentLength;


        public RecordReader(Stream innerStream, int maxFragmentLength)
        {
            DataBuffer = new byte[0x4800];
            dataLength = 0;
            dataOffset = 0;
            this.maxFragmentLength = maxFragmentLength;
            this.innerStream = innerStream;
        }

        ///<summary>Returns current offset of the loaded record in DataBuffer</summary>
        public int ReadNext()
        {
            ReachDataLength(RecordConst.HeaderLength);
            int fragmentLength = FixedRecordInfo.FragmentLength(DataBuffer, dataOffset);
            ReachDataLength(fragmentLength + RecordConst.HeaderLength);

            int currentHeaderOffset = dataOffset;
            
            dataOffset += fragmentLength + RecordConst.HeaderLength;
            dataLength -= fragmentLength + RecordConst.HeaderLength;

            if (dataLength == 0) dataOffset = 0;

            return currentHeaderOffset;
        }

        ///<summary>Ensures that in buffer is at least minDataLength bytes</summary>
        private void ReachDataLength(int minDataLength)
        {
            //already contains, nothing to do
            if(minDataLength <= dataLength) return;

            int totalFreeSpace = DataBuffer.Length  - dataLength;
            int appendFreeSpace = DataBuffer.Length - dataOffset - dataLength;
            int toReadLength = minDataLength - dataLength;

            //can append bytes without shifting anything ?
            if(appendFreeSpace < minDataLength)
            {
                //not enough space to append bytes/
                
                //need to extend buffer ? 
                if (totalFreeSpace >= minDataLength)
                {
                    ShiftDataToLeft();
                }
                else
                {
                    //yes, expand buffer and bytes
                    int toExpandLength = minDataLength - dataLength;
                    ExpandBuffer(DataBuffer.Length + toExpandLength - totalFreeSpace);
                    ShiftDataToLeft();
                }
                
            }
            AppendBytes(toReadLength);
        }

        private void AppendBytes(int minAppendCount)
        {
            int totalReaded = 0;

            while (minAppendCount > totalReaded)
            {
                int readed = innerStream.Read(DataBuffer, dataOffset + dataLength, minAppendCount - totalReaded);

                totalReaded += readed;
                dataLength += readed;
            }
        }

        private void ExpandBuffer(int newSize)
        {
            byte[] newBuf = new byte[newSize];
            Buffer.BlockCopy(DataBuffer, dataOffset, newBuf, 0, dataLength);
            DataBuffer = newBuf;
            dataOffset = 0;
        }

        private void ShiftDataToLeft()
        {
            if (dataOffset == 0) return;

            Buffer.BlockCopy(DataBuffer, dataOffset, DataBuffer, 0, dataLength);
            dataOffset = 0;
        }
    }
}
