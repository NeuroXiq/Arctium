using Arctium.Connection.Tls.Protocol.RecordProtocol;
using System.IO;
using System;
using Arctium.Connection.Tls.Protocol.FormatConsts;
using Arctium.Connection.Tls.Protocol.BinaryOps.FixedOps;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12
{
    // Optimized record reader
    //


    ///<summary>This class facilitate work with tls records</summary>
    class RecordsBuffer
    {
        public byte[] DataBuffer { get; private set; }

        int dataLength;
        int dataOffset;

        Stream innerStream;
        int maxFragmentLength;


        public RecordsBuffer(Stream innerStream, int maxFragmentLength)
        {
            DataBuffer = new byte[0x100];
            dataLength = 0;
            dataOffset = 0;
            this.maxFragmentLength = maxFragmentLength;
            this.innerStream = innerStream;
        }

        public int Read()
        {
            EnsureDataLength(RecordConst.HeaderLength);

            int fragmentLength = FixedRecordInfo.FragmentLength(DataBuffer, dataOffset);

            //if(fragmentLength > maxFragmentLength) 

            EnsureDataLength(fragmentLength);

            int currentRecordOffset = dataOffset;

            //shift offset, preparing to next read
            //internal state about currently readed record (in this method) is lost
            dataOffset += fragmentLength + RecordConst.HeaderLength;
            dataLength -= fragmentLength + RecordConst.HeaderLength;

            return currentRecordOffset;
        }

        private void EnsureDataLength(int count)
        {
            if (count > dataLength)
            {
                EnsureWriteSize(count);

                while (count > dataLength)
                {
                    int appendMaxSize = DataBuffer.Length - dataOffset - dataLength;
                    int readedFromStream = innerStream.Read(DataBuffer, dataOffset + dataLength, appendMaxSize);
                    dataLength += readedFromStream;
                }
            }
        }

        private void EnsureWriteSize(int writeCount)
        {
            if (writeCount + dataOffset >= DataBuffer.Length)
            {
                int freeSpaceInBuffer = DataBuffer.Length - dataLength;

                if (freeSpaceInBuffer < writeCount)
                {
                    byte[] newBuf = new byte[writeCount - freeSpaceInBuffer + dataLength];
                    Buffer.BlockCopy(DataBuffer, dataOffset, newBuf, 0, dataLength);

                    dataOffset = 0;
                    DataBuffer = newBuf;
                }
                else
                {
                    Buffer.BlockCopy(DataBuffer, dataOffset, DataBuffer, 0, dataLength);
                    dataOffset = 0;
                }
            }
        }
    }
}
