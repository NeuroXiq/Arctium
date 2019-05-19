using System.Security.Cryptography;
using System;
using Arctium.Connection.Tls.Protocol.BinaryOps;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12
{
    class StreamFragmentCrypto : IFragmentDecryptor, IFragmentEncryptor
    {
        HMAC hmac;
        SymmetricAlgorithm cipher;

        public StreamFragmentCrypto(HMAC hmac, SymmetricAlgorithm symmetricAlgorithm)
        {
            this.hmac = hmac;
            this.cipher = symmetricAlgorithm;
        }

        public int Encrypt(RecordData recordData, byte[] outBuffer, int outOffset)
        {
            byte[] hmac = ComputeEncryptHmac(recordData);
            Buffer.BlockCopy(hmac, 0, outBuffer, outOffset + recordData.Header.FragmentLength, hmac.Length);

            ICryptoTransform encryptor = cipher.CreateEncryptor();

            encryptor.TransformBlock(recordData.Buffer, recordData.FragmentOffset, recordData.Header.FragmentLength, outBuffer, outOffset);

            return hmac.Length + recordData.Header.FragmentLength;
        }

        private byte[] ComputeEncryptHmac(RecordData recordData)
        {

            byte[] seedBlock = new byte[14];

            NumberConverter.FormatUInt64(recordData.SeqNum, seedBlock, 0);

            seedBlock[8] =  (byte)recordData.Header.ContentType;
            seedBlock[9] = (byte)recordData.Header.Version.Major;
            seedBlock[10] = (byte)recordData.Header.Version.Minor;

            NumberConverter.FormatUInt24(recordData.Header.FragmentLength, seedBlock, 11);


            hmac.TransformBlock(seedBlock, 0, seedBlock.Length, null, 0);
            hmac.TransformFinalBlock(recordData.Buffer, recordData.FragmentOffset, recordData.Header.FragmentLength);

            return hmac.Hash;
        }

        public int Decrypt(RecordData recordData, byte[] outBuffer, int outOffset)
        {
            ICryptoTransform decryptor = cipher.CreateDecryptor();
            int contentLength = decryptor.TransformBlock(recordData.Buffer, recordData.FragmentOffset, recordData.Header.FragmentLength, outBuffer, outOffset);


            byte[] hmac = Computehmac(outBuffer, outOffset, contentLength, recordData);

            //validate hmac


            return contentLength;
        }

        private byte[] Computehmac(byte[] contentBuffer, int contentOffset, int contentLength, RecordData recordData)
        {
            byte[] seedBlock = new byte[14];

            NumberConverter.FormatUInt64(recordData.SeqNum, seedBlock, 0);

            seedBlock[8] = (byte)recordData.Header.ContentType;
            seedBlock[9] = (byte)recordData.Header.Version.Major;
            seedBlock[10] = (byte)recordData.Header.Version.Minor;

            NumberConverter.FormatUInt24(recordData.Header.FragmentLength, seedBlock, 11);

            hmac.TransformBlock(seedBlock, 0, seedBlock.Length, null, 0);
            hmac.TransformFinalBlock(contentBuffer, contentOffset, contentLength);

            return hmac.Hash;
        }

        public int GetEncryptedLength(int contentPlaintextLength)
        {
            return contentPlaintextLength + (hmac.HashSize / 8);
        }

        public int GetDecryptedLength(int ciphertextFragmentLength)
        {
            int length = ciphertextFragmentLength - (hmac.HashSize / 8) - (cipher.BlockSize / 8);

            if (length < 0) throw new InvalidOperationException("ciphertext fragment length is less than possible");

            return length;
        }
    }
}
