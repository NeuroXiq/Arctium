using System.Security.Cryptography;
using System;
using Arctium.Standards.Connection.Tls.Protocol.BinaryOps;
using Arctium.Standards.Connection.Tls.Protocol.RecordProtocol;
using System.IO;
using Arctium.Standards.Connection.Tls.Protocol.BinaryOps.FixedOps;
using Arctium.Standards.Connection.Tls.Protocol.Consts;

namespace Arctium.Standards.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12
{
    class StreamFragmentCrypto : IRecordCryptoFilter
    {
        HMAC hmac;
        SymmetricAlgorithm cipher;

        int macSize;

        RecordReader recordReader;
        Stream writeStream;

        ulong writeSeqNum;
        ulong readSeqNum;

        //resuable write record buffer
        byte[] recordWriteBuffer;

        public StreamFragmentCrypto(HMAC hmac, SymmetricAlgorithm symmetricAlgorithm)
        {
            this.hmac = hmac;
            macSize = hmac.HashSize / 8;
            cipher = symmetricAlgorithm;
            writeSeqNum = readSeqNum = 0;
            recordWriteBuffer = new byte[0];
        }

        public void SetRecordReader(RecordReader recordReader)
        {
            this.recordReader = recordReader;
        }

        public void SetWriteStream(Stream writeStream)
        {
            this.writeStream = writeStream;
        }

        public void SetReadSequenceNumber(ulong seqNum)
        {
            readSeqNum = seqNum;
        }

        public void SetWriteSequenceNumber(ulong seqNum)
        {
            writeSeqNum = seqNum;
        }

        public int ReadFragment(byte[] buffer, int offset, out ContentType contentType)
        {
            int recordOffset = recordReader.ReadNext();
            RecordHeader header = FixedRecordInfo.GetHeader(recordReader.DataBuffer, recordOffset);

            var decryptor = cipher.CreateDecryptor();
            int decryptedCount = 
                decryptor.TransformBlock(recordReader.DataBuffer, recordOffset + RecordConst.HeaderLength, header.FragmentLength - macSize, buffer, offset);

            contentType = header.ContentType;

            readSeqNum++;
            return decryptedCount;
        }

        public void WriteFragment(byte[] buffer, int offset, int length, ContentType contentType)
        {
            if (length > RecordConst.MaxTlsPlaintextFramentLength) throw new Exception("Length exceed record fragment length limit. Partition data first");

            int totalRecordLength = length + RecordConst.HeaderLength + macSize;
            if (totalRecordLength > recordWriteBuffer.Length) recordWriteBuffer = new byte[totalRecordLength];
            int ciphertextFragmentLength = length + macSize;


            //record formatting
            recordWriteBuffer[0] = (byte)contentType;
            recordWriteBuffer[1] = 3;
            recordWriteBuffer[2] = 3;
            NumberConverter.FormatUInt16((ushort)ciphertextFragmentLength, recordWriteBuffer, 3);

            var encryptor = cipher.CreateEncryptor();

            int encryptedCount = encryptor.TransformBlock(buffer, offset, length, recordWriteBuffer, 5);

            byte[] mac = ComputeHmac(writeSeqNum, contentType, buffer, offset, length);

            Buffer.BlockCopy(mac, 0, recordWriteBuffer, RecordConst.HeaderLength + encryptedCount, mac.Length);

            writeStream.Write(recordWriteBuffer, 0, totalRecordLength);

            writeSeqNum++;   
        }

        private byte[] ComputeHmac(ulong seqNum, ContentType contentType, byte[] buffer, int offset, int length)
        {
            if (macSize == 0) return new byte[0];

            byte[] prefix = new byte[13];
            NumberConverter.FormatUInt64(seqNum, prefix, 0);
            prefix[8] = (byte)contentType;
            prefix[9] = 3;
            prefix[10] = 3;
            NumberConverter.FormatUInt16((ushort)length, prefix, 11);

            byte[] holdKey = hmac.Key;
            hmac.Initialize();
            hmac.Key = holdKey;

            hmac.TransformBlock(prefix, 0, prefix.Length, null, 0);
            hmac.TransformFinalBlock(buffer, offset, length);

            return hmac.Hash;
        }
    }
}
