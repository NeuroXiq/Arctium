using Arctium.Connection.Tls.CryptoConfiguration;
using Arctium.Connection.Tls.Protocol;
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
        RecordsBuffer recordsReadBuffer;

        RecordCrypto writeRecordCrypto;
        RecordCrypto readRecordCrypto;

        ulong readSeqNum;
        ulong writeSeqNum;

        byte[] sendReusableBuffer;
        Stream innerStream;

        RecordLayer12(Stream innerStream)
        {
            recordsReadBuffer = new RecordsBuffer(innerStream, RecordConst.MaxTlsRecordLength);
            sendReusableBuffer = new byte[0];
            this.innerStream = innerStream;
        }

        public static RecordLayer12 Initialize(Stream innerStream)
        {
            RecordLayer12 recordLayer =  new RecordLayer12(innerStream);

            recordLayer.ChangeReadCipherSpec(RecordCryptoFactory.InitReadSecParams);
            recordLayer.ChangeWriteCipherSpec(RecordCryptoFactory.InitWriteSecParams);

            return recordLayer;
        }

        public FragmentData ReadFragment(out ContentType type)
        {
            int recordOffset = recordsReadBuffer.Read();
            int fragmentOffset = recordOffset + RecordConst.HeaderLength;
            type = FixedRecordInfo.GetContentType(recordsReadBuffer.DataBuffer, recordOffset);

            if (FixedRecordInfo.FragmentLength(recordsReadBuffer.DataBuffer, recordOffset) < 1) throw new Exception("record length == 0");


            // decryption info
            RecordCrypto.RecordData data = new RecordCrypto.RecordData();
            data.Buffer = recordsReadBuffer.DataBuffer;
            data.FragmentOffset = fragmentOffset;
            data.SeqNum = readSeqNum;

            // decrypt bytes in buffer
            int contentLength = readRecordCrypto.Decrypt(data, data.Buffer, data.FragmentOffset);

            // now fragmentsBuffer contains decrypted fragment

            FragmentData resultData = new FragmentData(recordsReadBuffer.DataBuffer, fragmentOffset , contentLength);
            readSeqNum++;

            return resultData;
        }

        public void WriteFragment(byte[] buffer, int offset, int length, ContentType contentType)
        {
            if (writeRecordCrypto.GetEncryptedLength(length) < sendReusableBuffer.Length - RecordConst.HeaderLength)
            {
                sendReusableBuffer = new byte[writeRecordCrypto.GetEncryptedLength(length) + RecordConst.HeaderLength];
            }

            sendReusableBuffer[0] = (byte)contentType;
            sendReusableBuffer[1] = 3;
            sendReusableBuffer[2] = 3;

            NumberConverter.FormatUInt16((ushort)length, sendReusableBuffer, 3);

            RecordCrypto.RecordData data = new RecordCrypto.RecordData();
            data.Buffer = buffer;
            data.FragmentOffset = 5;
            data.SeqNum = writeSeqNum;
            data.FragmentOffset = offset;
            data.Header = new RecordHeader(contentType, new ProtocolVersion(3, 3), length);

            int encryptedLength = writeRecordCrypto.Encrypt(data, sendReusableBuffer, 5);

            innerStream.Write(sendReusableBuffer, 0, encryptedLength + RecordConst.HeaderLength);

        }

        public void ChangeWriteCipherSpec(SecParams12 secParams)
        {
            writeSeqNum = 0;
            writeRecordCrypto = RecordCryptoFactory.CreateRecordCrypto(secParams);
        }

        public void ChangeReadCipherSpec(SecParams12 secParams)
        {
            readSeqNum = 0;
            readRecordCrypto = RecordCryptoFactory.CreateRecordCrypto(secParams);
        }
    }
}
