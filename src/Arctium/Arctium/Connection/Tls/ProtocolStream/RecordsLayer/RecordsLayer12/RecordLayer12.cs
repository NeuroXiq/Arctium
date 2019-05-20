﻿using Arctium.Connection.Tls.CryptoConfiguration;
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

        IFragmentEncryptor writeRecordCrypto;
        IFragmentDecryptor readRecordCrypto;

        ulong readSeqNum;
        ulong writeSeqNum;

        byte[] reusableEncryptBuffer;
        Stream innerStream;

        RecordLayer12(Stream innerStream)
        {
            recordsReadBuffer = new RecordsBuffer(innerStream, RecordConst.MaxTlsRecordLength);
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

        public FragmentData ReadFragment(out ContentType type)
        {
            int recordOffset = recordsReadBuffer.ReadNext();
            int fragmentOffset = recordOffset + RecordConst.HeaderLength;
            type = FixedRecordInfo.GetContentType(recordsReadBuffer.DataBuffer, recordOffset);

            if (FixedRecordInfo.FragmentLength(recordsReadBuffer.DataBuffer, recordOffset) < 1) throw new Exception("record length == 0");


            // decryption info
            RecordData data = new RecordData();
            data.Buffer = recordsReadBuffer.DataBuffer;
            data.Header = FixedRecordInfo.GetHeader(recordsReadBuffer.DataBuffer, recordOffset);
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
            if (writeRecordCrypto.GetEncryptedLength(length) > reusableEncryptBuffer.Length - RecordConst.HeaderLength)
            {
                reusableEncryptBuffer = new byte[writeRecordCrypto.GetEncryptedLength(length) + RecordConst.HeaderLength];
            }

            reusableEncryptBuffer[0] = (byte)contentType;
            reusableEncryptBuffer[1] = 3;
            reusableEncryptBuffer[2] = 3;

            //NumberConverter.FormatUInt16((ushort)length, reusableEncryptBuffer, 3);

            RecordData data = new RecordData();
            data.Buffer = buffer;
            data.FragmentOffset = offset;
            data.SeqNum = writeSeqNum;
            data.Header = new RecordHeader(contentType, new ProtocolVersion(3, 3), length);

            int encryptedLength = writeRecordCrypto.Encrypt(data, reusableEncryptBuffer, 5);

            NumberConverter.FormatUInt16((ushort)encryptedLength, reusableEncryptBuffer, 3);

            innerStream.Write(reusableEncryptBuffer, 0, encryptedLength + RecordConst.HeaderLength);

            writeSeqNum++;
        }

        public void ChangeWriteCipherSpec(RecordLayer12Params secParams)
        {
            writeSeqNum = 0;
            writeRecordCrypto = RecordCryptoFactory.CreateEncryptor(secParams);
           
        }

        public void ChangeReadCipherSpec(RecordLayer12Params secParams)
        {
            readSeqNum = 0;
            readRecordCrypto = RecordCryptoFactory.CreateDecryptor(secParams);
        }
    }
}
