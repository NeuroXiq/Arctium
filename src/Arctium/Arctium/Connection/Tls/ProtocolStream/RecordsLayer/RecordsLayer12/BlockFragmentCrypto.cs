using Arctium.Connection.Tls.Protocol.BinaryOps;
using System;
using System.Security.Cryptography;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12
{
    class BlockFragmentCrypto : IFragmentDecryptor, IFragmentEncryptor
    {
        HMAC hmac;
        SymmetricAlgorithm cipher;

        int hmacSize;
        int blockSize;

        public BlockFragmentCrypto(HMAC hmac, SymmetricAlgorithm cipher)
        {
            this.hmac = hmac;
            this.cipher = cipher;

            hmacSize = hmac.HashSize / 8;
            blockSize = cipher.BlockSize / 8;
        }

        public int Decrypt(RecordData recordData, byte[] outBuffer, int outOffset)
        {
            byte[] iv = GetIV(recordData);


            //byte[] decryptedData = new byte[recordData.Header.FragmentLength - iv.Length];
            //Buffer.BlockCopy(recordData.Buffer, recordData.FragmentOffset, encryptedData, 0, recordData.Header.FragmentLength - iv.Length);

            var decryptor = cipher.CreateDecryptor(cipher.Key, iv);

            int decryptedCount = decryptor.TransformBlock(
                recordData.Buffer, 
                recordData.FragmentOffset+iv.Length,
                recordData.Header.FragmentLength - iv.Length,
                outBuffer,
                outOffset);

            int paddingLength = outBuffer[outOffset + decryptedCount - 1] + 1;// decryptedData[decryptedData.Length - 1] + 1;

            int contentOffset = outOffset;
            int contentLength = recordData.Header.FragmentLength - iv.Length - paddingLength - hmacSize;
            int macOffset = contentOffset + contentLength;

            byte[] readedHmac = new byte[hmacSize];
            Buffer.BlockCopy(outBuffer, outOffset +  decryptedCount - paddingLength - hmacSize, readedHmac, 0, hmacSize);

            byte[] computedHmac = ComputeHmac(recordData, outBuffer, outOffset, contentLength);

            for (int i = 0; i < readedHmac.Length; i++)
            {
                if (readedHmac[i] != computedHmac[i]) throw new Exception("invalid hmac");
            }

            return contentLength;
        }

        private byte[] GetIV(RecordData recordData)
        {
            byte[] iv = new byte[blockSize];
            Buffer.BlockCopy(recordData.Buffer, recordData.FragmentOffset, iv, 0, blockSize);

            return iv;
        }

        public int Encrypt(RecordData recordData, byte[] outBuffer, int outOffset)
        {

            byte[] hmac = ComputeHmac(recordData, recordData.Buffer, recordData.FragmentOffset, recordData.Header.FragmentLength);
            byte[] iv = CreateIV();
            byte[] padding = CreatePadding(recordData.Header.FragmentLength + iv.Length + hmac.Length);


            int ivOffset = outOffset;
            int contentOffset = outOffset + blockSize;
            int hmacOffset = contentOffset + recordData.Header.FragmentLength;
            int paddingOffset = hmacOffset + hmacSize;

            int totalLength = blockSize + recordData.Header.FragmentLength + hmacSize + padding.Length;
            int toEncryptLength = totalLength - iv.Length;
            int toEncryptOffset = contentOffset;

            byte[] encryptedBytes = new byte[toEncryptLength];
            byte[] plainBytes = new byte[toEncryptLength];

            //Buffer.BlockCopy(iv, 0, outBuffer, ivOffset, iv.Length);
            Buffer.BlockCopy(recordData.Buffer, recordData.FragmentOffset, plainBytes, 0, recordData.Header.FragmentLength);
            Buffer.BlockCopy(hmac, 0, plainBytes, recordData.Header.FragmentLength, hmac.Length);
            Buffer.BlockCopy(padding, 0, plainBytes, recordData.Header.FragmentLength + hmac.Length, padding.Length);

            var encryptor = cipher.CreateEncryptor(cipher.Key, iv);
            int encryptedCount = encryptor.TransformBlock(plainBytes, 0, plainBytes.Length, encryptedBytes, 0);

            Buffer.BlockCopy(iv, 0, outBuffer, outOffset, iv.Length);
            Buffer.BlockCopy(encryptedBytes, 0, outBuffer, iv.Length + outOffset, encryptedBytes.Length);

            
            return totalLength;
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

        private byte[] ComputeHmac(RecordData recordData, byte[] buffer,int offset, int length)
        {
            byte[] prefix = new byte[8 + 1 + 2 + 2];

            NumberConverter.FormatUInt64(recordData.SeqNum, prefix, 0);
            prefix[8] = (byte)recordData.Header.ContentType;
            prefix[9] = recordData.Header.Version.Major;
            prefix[10] = recordData.Header.Version.Minor;
            NumberConverter.FormatUInt16((ushort)length, prefix, 11);

            byte[] k = hmac.Key;
            hmac.Initialize();
            hmac.Key = k;
            hmac.TransformBlock(prefix, 0, prefix.Length, null, 0);
            hmac.TransformFinalBlock(buffer, offset, length);

            return hmac.Hash;

        }

        public int GetEncryptedLength(int plaintextFragmentLength)
        {
            int paddingLength = blockSize - ((plaintextFragmentLength + 1) % blockSize);

            return blockSize + plaintextFragmentLength + hmacSize + paddingLength;
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
    }
}
