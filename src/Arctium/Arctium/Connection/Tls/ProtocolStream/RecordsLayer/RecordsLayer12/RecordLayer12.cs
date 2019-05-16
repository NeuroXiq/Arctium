using Arctium.Connection.Tls.Buffers;
using Arctium.Connection.Tls.CryptoConfiguration;
using Arctium.Connection.Tls.Protocol.BinaryOps.FixedOps;
using Arctium.Connection.Tls.Protocol.RecordProtocol;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer;
using System.IO;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12
{
    class RecordLayer12
    {
        RecordsBuffer recordsReadBuffer;

        RecordCrypto writeCrypto;
        RecordCrypto readCrypto;

        ulong readSeqNum;
        ulong writeSeqNum;

        byte[] sendReusableBuffer;

        RecordLayer12(Stream innerStream)
        {
            recordsReadBuffer = new RecordsBuffer();
            sendReusableBuffer = new byte[0];
        }

        public RecordLayer12 Initialize(Stream innerStream)
        {
            RecordLayer12 recordLayer =  new RecordLayer12(innerStream);

            recordLayer.ChangeReadCipherSpec(RecordCryptoFactory.InitReadSecParams);
            recordLayer.ChangeWriteCipherSpec(RecordCryptoFactory.InitWriteSecParams);

            return recordLayer;
        }

        public FragmentData LoadFragment(out ContentType type)
        {
            recordsReadBuffer.GoToNextRecord();

            //decryption info
            RecordCrypto.RecordData data = new RecordCrypto.RecordData();
            data.Buffer = recordsReadBuffer.DataBuffer;
            data.RecordOffset = recordsReadBuffer.Cursor.RecordOffset;
            data.SeqNum = readSeqNum;

            int contentOffset;
            // decrypt bytes in buffer
            int contentLength = readCrypto.Decrypt(data, out contentOffset);

            // now fragmentsBuffer contains decrpyted fragment

            FragmentData resultData = new FragmentData(recordsReadBuffer.DataBuffer, contentOffset, contentLength);
            readSeqNum++;

            type = recordsReadBuffer.Cursor.Header.ContentType;

            return resultData;
        }

        public void ChangeWriteCipherSpec(SecParams12 secParams)
        {
            writeSeqNum = 0;
            writeCrypto = RecordCryptoFactory.CreateRecordCrypto(secParams);
        }

        public void ChangeReadCipherSpec(SecParams12 secParams)
        {
            readSeqNum = 0;
            readCrypto = RecordCryptoFactory.CreateRecordCrypto(secParams);
        }
    }
}
