using Arctium.Connection.Tls.Protocol.BinaryOps;
using Arctium.Connection.Tls.Protocol.BinaryOps.FixedOps;
using Arctium.Connection.Tls.Protocol.FormatConsts;
using Arctium.Connection.Tls.Protocol.RecordProtocol;
using System;
using System.IO;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12
{
    class RecordLayer12
    {
        RecordReader recordReader;

        IRecordCryptoFilter readCryptoFilter;
        IRecordCryptoFilter writeCryptoFilter;

        ulong readSeqNum;
        ulong writeSeqNum;

        byte[] reusableEncryptBuffer;
        Stream innerStream;

        RecordLayer12(Stream innerStream)
        {
            recordReader = new RecordReader(innerStream, RecordConst.MaxTlsRecordLength);
            reusableEncryptBuffer = new byte[0];
            this.innerStream = innerStream;
        }

        public static RecordLayer12 Initialize(Stream innerStream)
        {
            RecordLayer12 recordLayer =  new RecordLayer12(innerStream);

            recordLayer.ChangeReadCipherSpec(RecordCryptoFactory.InitReadSecParams);
            recordLayer.ChangeWriteCipherSpec(RecordCryptoFactory.InitWriteSecParams);

            return recordLayer;
        }

        
        public int ReadFragment(byte[] buffer, int offset, out ContentType type)
        {
            return readCryptoFilter.ReadFragment(buffer, offset, out type);
        }

        ///<summary>Writes higher level protocol bytes of the specified <paramref="contentType"/></summary>
        public void Write(byte[] buffer, int offset, int length, ContentType contentType)
        {
            if (length == 0) throw new InvalidOperationException("length of the fragment cannot be zero");

            int writeOffset = 0;
            int maxWriteLength = 0x4800;

            while (writeOffset + maxWriteLength <= length)
            {
                writeCryptoFilter.WriteFragment(buffer, offset + writeOffset, maxWriteLength, contentType);
            }

            writeCryptoFilter.WriteFragment(buffer, writeOffset, length - writeOffset, contentType);

        }

        public void ChangeWriteCipherSpec(RecordLayer12Params secParams)
        {
            writeSeqNum = 0;
            writeCryptoFilter = RecordCryptoFactory.CreateRecordCryptoFilter(secParams);

            writeCryptoFilter.SetReadSequenceNumber(0);
            writeCryptoFilter.SetWriteStream(innerStream);
        }

        public void ChangeReadCipherSpec(RecordLayer12Params secParams)
        {
            readSeqNum = 0;
            readCryptoFilter = RecordCryptoFactory.CreateRecordCryptoFilter(secParams);

            readCryptoFilter.SetReadSequenceNumber(0);
            readCryptoFilter.SetRecordReader(recordReader);
        }
    }
}
