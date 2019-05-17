using System.Security.Cryptography;
using System;
using Arctium.Connection.Tls.Protocol.BinaryOps;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12
{
    class StreamRecordCrypto : RecordCrypto
    {
        HMAC encryptHmac;
        HMAC decryptHmac;
        SymmetricAlgorithm encryptCipher;
        SymmetricAlgorithm decryptCipher;
        

        public StreamRecordCrypto(HMAC encryptHmac, HMAC decryptHmac, SymmetricAlgorithm encryptAlgo, SymmetricAlgorithm decryptAlgo)
        {
            this.encryptHmac = encryptHmac;
            this.decryptHmac = decryptHmac;
            this.encryptCipher = encryptAlgo;
            this.decryptCipher = decryptAlgo;
        }

        public override int Encrypt(RecordData recordData, byte[] outBuffer, int outOffset)
        {
            byte[] hmac = ComputeEncryptHmac(recordData);
            Buffer.BlockCopy(hmac, 0, outBuffer, outOffset + recordData.Header.FragmentLength, hmac.Length);

            ICryptoTransform encryptor = decryptCipher.CreateEncryptor();

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


            encryptHmac.TransformBlock(seedBlock, 0, seedBlock.Length, null, 0);
            encryptHmac.TransformFinalBlock(recordData.Buffer, recordData.FragmentOffset, recordData.Header.FragmentLength);

            return encryptHmac.Hash;
        }

        public override int Decrypt(RecordData recordData, byte[] outBuffer, int outOffset)
        {
            ICryptoTransform decryptor = decryptCipher.CreateDecryptor();
            int contentLength = decryptor.TransformBlock(recordData.Buffer, recordData.FragmentOffset, recordData.Header.FragmentLength, outBuffer, outOffset);


            byte[] hmac = ComputeDecryptHmac(outBuffer, outOffset, contentLength, recordData);

            //validate hmac


            return contentLength;
        }

        private byte[] ComputeDecryptHmac(byte[] contentBuffer, int contentOffset, int contentLength, RecordData recordData)
        {
            byte[] seedBlock = new byte[14];

            NumberConverter.FormatUInt64(recordData.SeqNum, seedBlock, 0);

            seedBlock[8] = (byte)recordData.Header.ContentType;
            seedBlock[9] = (byte)recordData.Header.Version.Major;
            seedBlock[10] = (byte)recordData.Header.Version.Minor;

            NumberConverter.FormatUInt24(recordData.Header.FragmentLength, seedBlock, 11);

            decryptHmac.TransformBlock(seedBlock, 0, seedBlock.Length, null, 0);
            decryptHmac.TransformFinalBlock(contentBuffer, contentOffset, contentLength);

            return decryptHmac.Hash;
        }

        public override int GetEncryptedLength(int contentPlaintextLength)
        {
            return contentPlaintextLength + (encryptHmac.HashSize / 8);
        }

        public override int GetDecryptedLength(int ciphertextFragmentLength)
        {
            int length = ciphertextFragmentLength - (decryptHmac.HashSize / 8);

            if (length < 0) throw new InvalidOperationException("ciphertext fragment length is less than possible");

            return length;
        }
    }
}
