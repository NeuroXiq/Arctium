using Arctium.Protocol.Tls.Protocol.BinaryOps;
using System;
using System.Security.Cryptography;
using Arctium.Protocol.Tls.Protocol;
using Arctium.Protocol.Tls.Protocol.RecordProtocol;
using System.IO;
using Arctium.Protocol.Tls.Protocol.BinaryOps.FixedOps;
using Arctium.Protocol.Tls.Protocol.Consts;
using Arctium.Protocol.Tls.Exceptions;
using Arctium.Protocol.Tls.Protocol.AlertProtocol;

namespace Arctium.Protocol.Tls.ProtocolStream.RecordsLayer.RecordsLayer12
{
    class BlockFragmentCrypto : IRecordCryptoFilter
    {
        HMAC hmac;
        SymmetricAlgorithm cipher;

        byte[] internalDecryptBuffer;
        byte[] internalEncryptBuffer;

        int macSize;
        int blockSize;
        RecordReader recordReader;
        Stream writeStream;
        ulong readSeqNum;
        ulong writeSeqNum;

        readonly int minimumFragmentLength;
        readonly int maximumFragmentLength;

        public BlockFragmentCrypto(HMAC hmac, SymmetricAlgorithm cipher)
        {
            this.hmac = hmac;
            this.cipher = cipher;

            macSize = hmac.HashSize / 8;
            blockSize = cipher.BlockSize / 8;

            //padding include 
            int minFragmentLen = macSize + blockSize;
            minimumFragmentLength = minFragmentLen + blockSize - (minFragmentLen % blockSize);

            //max padding length included
            int maxFragmLen = RecordConst.MaxTlsPlaintextFramentLength + macSize + blockSize;
            maximumFragmentLength = maxFragmLen + blockSize - (maxFragmLen % blockSize);

            internalDecryptBuffer = new byte[0];
            internalEncryptBuffer = new byte[0];

        }

        private byte[] GetIV(int recordReaderOffset)
        {
            byte[] iv = new byte[blockSize];
            Buffer.BlockCopy(recordReader.DataBuffer, recordReaderOffset, iv, 0, blockSize);

            return iv;
        }

        private byte[] CreateIV()
        {
            byte[] iv = new byte[blockSize];
            for (int i = 0; i < blockSize; i++)
            {
                iv[i] = (byte)i;
            }

            return iv;
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

        public byte[] CreatePadding(int baseLength)
        {
            int paddingLength = blockSize - ((baseLength) % blockSize);

            byte[] padding = new byte[paddingLength];
            for (int i = 0; i < paddingLength; i++)
            {
                padding[i] = (byte)(paddingLength - 1);
            }

            return padding;

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
            this.readSeqNum = seqNum;
        }

        public int ReadFragment(byte[] buffer, int offset, out ContentType contentType)
        {
            int recordOffset = recordReader.ReadNext();
            RecordHeader recordHeader = FixedRecordInfo.GetHeader(recordReader.DataBuffer, recordOffset);

            ThrowIfInvalidFragmentLength(recordHeader.FragmentLength);

            int ivOffset = recordOffset + RecordConst.HeaderLength;
            int encryptedContentOffset = ivOffset + blockSize;
            int encryptedContentCount = recordHeader.FragmentLength - blockSize;
            byte[] iv = GetIV(ivOffset);

            var decryptor = cipher.CreateDecryptor(cipher.Key, iv);
            int decryptedCount = decryptor.TransformBlock(recordReader.DataBuffer, encryptedContentOffset, encryptedContentCount, buffer, offset);

            ThrowIfInvalidPaddingOrMac(buffer, offset, decryptedCount, recordHeader);

            int paddingLength = buffer[offset + decryptedCount - 1] + 1;

            int plainContentLength = decryptedCount - macSize - paddingLength;


            contentType = recordHeader.ContentType;

            readSeqNum++;

            return plainContentLength;
        }

        private void ThrowIfInvalidFragmentLength(int fragmentLength)
        {
            if (minimumFragmentLength > fragmentLength) throw new FatalAlertException("RecordLayer12.BlockFragmentCrypto", "After read record", (int)AlertDescription.BadRecordMac, "Invalid fragment length, minimum not reached");
            if (maximumFragmentLength < fragmentLength) throw new FatalAlertException("RecordLayer12.BlockFragmentCrypto", "After read record", (int)AlertDescription.BadRecordMac, "Length of the fragment do not reach minimum value");
            if (fragmentLength % blockSize != 0) throw new FatalAlertException("RecordLayer12.BlockFragmentCrypto", "After read record", (int)AlertDescription.BadRecordMac, "Length of the received fragment is not a multiple of the block size");
        }

        //decrypted fragment (content + mac + padding), iv must not be included
        private void ThrowIfInvalidPaddingOrMac(byte[] buffer, int offset, int length, RecordHeader header)
        {
            int paddingLength = buffer[offset + length - 1] + 1;
            int paddingStartOffset = offset + length - paddingLength;

            int macOffset = offset + length - paddingLength - macSize;

            if (length - paddingLength < macSize + 1) throw new Exception("Invalid MAC (padding length value indicates that mac + 1 minimum bytes of content is not present in record)");
            for (int i = paddingStartOffset; i < paddingLength + paddingStartOffset; i++)
            {
                if (buffer[paddingStartOffset] != paddingLength - 1)
                    throw new Exception("Invalid padding value");
            }


            byte[] receivedHmac = new byte[macSize];
            Buffer.BlockCopy(buffer, macOffset, receivedHmac, 0, macSize);

            byte[] computedMac = ComputeHmac(readSeqNum, header.ContentType, buffer, offset, length - paddingLength - macSize);

            for (int i = 0; i < receivedHmac.Length; i++)
            {
                if (receivedHmac[i] != computedMac[i])
                    throw new Exception("Invalid hmac value, computed value are different in comparison to presented in record fragment");
            }
            

            

        }

        public void WriteFragment(byte[] buffer, int offset, int length, ContentType contentType)
        {
            byte[] padding = CreatePadding(length + macSize + blockSize);

            int totalFragmentLength = padding.Length + macSize + blockSize + length;
            int totalRecordLength = RecordConst.HeaderLength + totalFragmentLength;

            if (internalDecryptBuffer.Length < totalRecordLength) internalDecryptBuffer = new byte[totalRecordLength];
            if (internalEncryptBuffer.Length < totalRecordLength) internalEncryptBuffer = new byte[totalRecordLength];

            int contentOffset = 0; // (block size == iv length always)
            int macOffset = contentOffset + length;
            int paddingOffset = macOffset + macSize;

            int toEncryptLength = length + macSize + padding.Length;
            int encryptOutOffset = RecordConst.HeaderLength + blockSize;

            byte[] iv = CreateIV();
            byte[] mac = ComputeHmac(writeSeqNum, contentType, buffer, offset, length);

            //TODO optimization need 
            //
            Buffer.BlockCopy(buffer, offset, internalDecryptBuffer, contentOffset, length);
            Buffer.BlockCopy(mac, 0, internalDecryptBuffer, macOffset, macSize);
            Buffer.BlockCopy(padding, 0, internalDecryptBuffer, paddingOffset, padding.Length);

            var encryptor = cipher.CreateEncryptor(cipher.Key, iv);

            //encrypt plaint bytes in 'internalDecryptBuffer' and write encrypted to 'internalEncryptBuffer'
            encryptor.TransformBlock(internalDecryptBuffer, 0, toEncryptLength, internalEncryptBuffer, encryptOutOffset);

            //add record header and iv
            Buffer.BlockCopy(iv, 0, internalEncryptBuffer, RecordConst.HeaderLength, blockSize);

            internalEncryptBuffer[0] = (byte)contentType;
            internalEncryptBuffer[1] = 3;
            internalEncryptBuffer[2] = 3;
            NumberConverter.FormatUInt16((ushort)totalFragmentLength, internalEncryptBuffer, 3);

            writeStream.Write(internalEncryptBuffer, 0, totalRecordLength);

            writeSeqNum++;
        }

        public void SetWriteSequenceNumber(ulong seqNum)
        {
            this.writeSeqNum = seqNum;
        }
    }
}
