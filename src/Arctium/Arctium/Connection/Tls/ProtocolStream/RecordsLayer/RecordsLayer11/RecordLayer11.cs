using System;
using Arctium.Connection.Tls.CryptoConfiguration;
using Arctium.Connection.Tls.Protocol;
using System.Security.Cryptography;
using Arctium.Connection.Tls.Protocol.RecordProtocol;
using System.IO;
using Arctium.Connection.Tls.Protocol.BinaryOps;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer11
{
    class RecordLayer11
    {
        static readonly SecParams11 InitialSecParams11 = new SecParams11()
        {
            BulkReadKey = new byte[0],
            BulkWriteKey = new byte[0],
            MacReadKey = new byte[0],
            MacWriteKey = new byte[0],
            MasterSecret = new byte[0],
            CompressionMethod = CompressionMethod.NULL,

            RecordCryptoType = new RecordCryptoType(
                CipherType.Stream,
                BlockCipherMode.CBC,
                BulkCipherAlgorithm.NULL,
                0,
                MACAlgorithm.NULL)
        };

        struct ReadedRecord
        {
            public byte[] Fragment;
            public RecordHeader RecordHeader;

            public ReadedRecord(byte[] fragmnet, RecordHeader header)
            {
                Fragment = fragmnet;
                RecordHeader = header;
            }
        }

        const int FragmentWriteLength = 100;

        SecParams11 currentSecParams;

        CipherType currentCipherType { get { return currentSecParams.RecordCryptoType.CipherType; } }
        MACAlgorithm MacAlgorithm { get { return currentSecParams.RecordCryptoType.MACAlgorithm; } }

        byte[] BulkReadKey { get { return currentSecParams.BulkReadKey; } }
        byte[] BulkWriteKey { get { return currentSecParams.BulkWriteKey; } }
        byte[] MacReadKey { get { return currentSecParams.MacReadKey; } }
        byte[] MacWriteKey { get { return currentSecParams.MacWriteKey; } }

        //public int FragmentWriteLength { get; private set; }

        HMAC readHMAC;
        HMAC writeHMAC;
        SymmetricAlgorithm readCipher;
        SymmetricAlgorithm writeCipher;

        RecordIO recordIO;

        private ulong readSequenceNumber;
        private ulong writeSequenceNumber;



        private RecordLayer11(RecordIO recordIO)
        {
            this.recordIO = recordIO;
            readSequenceNumber = 0xffffffffffffffff;
            writeSequenceNumber = 0xffffffffffffffff;
        }


        ///<summary>Creates initial state of the RecordLayerv11</summary>
        public static RecordLayer11 Initialize(RecordIO innerRecordIO)
        {
            RecordLayer11 recordLayer = new RecordLayer11(innerRecordIO);
            recordLayer.ChangeCipherSpec(InitialSecParams11);

            return recordLayer;
        }

        public void ChangeCipherSpec(SecParams11 newSecParams11)
        {
            this.currentSecParams = newSecParams11;

            readHMAC = RecordLayer11CryptoFactory.GetReadHMAC(newSecParams11);
            writeHMAC = RecordLayer11CryptoFactory.GetWriteHMAC(newSecParams11);
            readCipher = RecordLayer11CryptoFactory.GetReadCipher(newSecParams11);
            writeCipher = RecordLayer11CryptoFactory.GetWriteCipher(newSecParams11);

            readSequenceNumber = 0;
            writeSequenceNumber = 0;
        }

        public void Write(byte[] buffer, int offset, int length, ContentType contentType)
        {
            switch (currentCipherType)
            {
                case CipherType.Stream: WriteAsGenericStreamCipher(buffer, offset, length, contentType); break;
                case CipherType.Block: WriteAsGenericBlockCipher(buffer, offset, length, contentType);   break;

                default: throw new Exception("Internal error, cipher type unrecognized (should never throw), improve secparam11 validation process");
            }
        }

        private void WriteAsGenericBlockCipher(byte[] buffer, int offset, int length, ContentType contentType)
        {
            byte[] iv = CreateIV();
            byte[] padding = CreatePadding(length);
            byte[] hmac = ComputeWriteHMAC(buffer, offset, length);

            int fragmentLength = iv.Length + padding.Length + length + hmac.Length;
            byte[] ciphertextFragment = new byte[fragmentLength];

            int paddingOffset = fragmentLength - padding.Length;
            int hmacOffset = paddingOffset - hmac.Length;
            int toEncryptOffset = iv.Length;
            int toEncryptCount = length + padding.Length + hmac.Length;
            int ivOffset = 0;


            // ciphertextFragment:
            //     [need encryption x x x ]
            // [IV][Content][HMAC][padding]
            //

            Buffer.BlockCopy(iv, 0, ciphertextFragment, ivOffset, iv.Length);
            Buffer.BlockCopy(buffer, offset, ciphertextFragment, toEncryptOffset, length);
            Buffer.BlockCopy(hmac, 0, ciphertextFragment, hmacOffset, hmac.Length);
            Buffer.BlockCopy(padding, 0, ciphertextFragment, paddingOffset, padding.Length);

            var encryptor = writeCipher.CreateEncryptor(BulkWriteKey, iv);


            byte[] encrypted = new byte[ciphertextFragment.Length];
            Array.Copy(ciphertextFragment, encrypted, ciphertextFragment.Length);

            encryptor.TransformBlock(ciphertextFragment, toEncryptOffset, toEncryptCount, encrypted, iv.Length);

            recordIO.WriteFragment(encrypted, 0, encrypted.Length, contentType);
        }

        private byte[] ComputeWriteHMAC(byte[] buffer, int offset, int length)
        {
            byte[] hmac =  new byte[readHMAC.HashSize / 8];

            for (int i = 0; i < hmac.Length; i++)
            {
                hmac[i] = (byte)i;
            }
            
            return hmac;
        }

        private byte[] CreatePadding(int length)
        {
            int blockSize = readCipher.BlockSize / 8;
            int ivLength = readCipher.KeySize / 8;
            int macLength = CryptoConst.HashSize(MacAlgorithm) / 8;

            int totalLength = (length + ivLength + macLength + 1);

            int paddingLength = blockSize - (totalLength % blockSize);
            byte[] padding = new byte[paddingLength + 1];
            for (int i = 0; i < paddingLength + 1; i++)
            {
                padding[i] = (byte)(paddingLength);
            }

            return padding;
        }

        private byte[] CreateIV()
        {
            int length = readCipher.KeySize / 8;
            byte[] iv = new byte[length];
            for (int i = 0; i < length; i++)
            {
                iv[i] = (byte)i;
            }
            return iv;
        }

        private void WriteAsGenericStreamCipher(byte[] buffer, int offset, int length, ContentType contentType)
        {
            byte[] hmac = new byte[0]; // ComputeHmac ... 

            int totalToSend = hmac.Length + length;

            byte[] fragmentWithMac = new byte[FragmentWriteLength];
            Buffer.BlockCopy(hmac, 0, fragmentWithMac, 0, hmac.Length);

            if (totalToSend <= FragmentWriteLength)
            {
                Buffer.BlockCopy(buffer, offset, fragmentWithMac, hmac.Length, length);

                recordIO.WriteFragment(fragmentWithMac, 0, totalToSend, contentType);
            }
            else
            {
                Buffer.BlockCopy(buffer, offset, fragmentWithMac, hmac.Length, FragmentWriteLength - hmac.Length);

                int totalSended = 0;
                int bufferSendOffset = offset + FragmentWriteLength - hmac.Length;

                recordIO.WriteFragment(fragmentWithMac, 0, FragmentWriteLength, contentType);
                totalSended = FragmentWriteLength;

                while (totalToSend > totalSended + FragmentWriteLength)
                {
                    recordIO.WriteFragment(buffer, bufferSendOffset, FragmentWriteLength, contentType);

                    totalSended += FragmentWriteLength;
                    bufferSendOffset += FragmentWriteLength;
                }
                int remaining = totalToSend - totalSended;

                if(remaining > 0)
                {
                    recordIO.WriteFragment(buffer, bufferSendOffset, remaining, contentType);
                }
            }
        }

        public int Read(byte[] buffer, int offset, out ContentType contentType)
        {
            recordIO.LoadRecord();
            contentType = recordIO.RecordHeader.ContentType;

            switch (currentCipherType)
            {
                case CipherType.Stream: return ReadAsGenericStreamCipher(buffer, offset);
                case CipherType.Block:  return ReadAsGenericBlockCipher(buffer, offset);

                default: throw new Exception("Internal error, cipher type unrecognized (should never throw), improve secparam11 validation process");
            }
        }

        //Fragment format:
        //    [x x x ENCRYPTED x x x]
        //[IV][Content][MAC][Padding]
        //
        //[Padding] e.g. xx xx 06 06 06 06 06 06 06    (7 x 06 not 6 x 06 !)
        //  xx xx ==  last two bytes of the mac
        private int ReadAsGenericBlockCipher(byte[] buffer, int offset)
        {
            ReadedRecord record = ReadNext();
            byte[] fragment = record.Fragment;
            int macLength = CryptoConst.HashSize(MacAlgorithm) / 8;
            byte[] iv = GetIV(fragment);
            
            int encryptedSegmentOffset = iv.Length;
            int encryptedSegmentLength = fragment.Length - iv.Length;
            byte[] decryptedBytes = new byte[encryptedSegmentLength];


            var decryptor = readCipher.CreateDecryptor(BulkReadKey, iv);
            int decryptedBytesCount = decryptor.TransformBlock(fragment, encryptedSegmentOffset, encryptedSegmentLength, decryptedBytes, 0);

            int paddingLength = decryptedBytes[encryptedSegmentLength - 1] + 1;
            int decryptedMacOffset = (encryptedSegmentLength - paddingLength - macLength);

            int decryptedContentLength = encryptedSegmentLength - paddingLength - macLength; //fragment.Length - iv.Length - paddingLength - macLength;

            byte[] decryptedMac = new byte[macLength];
            Buffer.BlockCopy(decryptedBytes, decryptedMacOffset, decryptedMac, 0, macLength);

            ValidateReadHmacs(decryptedBytes, 0, decryptedContentLength, decryptedMac);

            



            return decryptedContentLength;
        }

        private bool ValidateReadHmacs(byte[] buffer, int offset, int dataLength, byte[] decryptedMac)
        {
            int macLength = CryptoConst.HashSize(MacAlgorithm);
            if (macLength == 0)
            {
                if (decryptedMac.Length == 0) return true;
                else return false;
            }

            readHMAC.Initialize();
            readHMAC.Key = MacReadKey;

            byte[] seqNumBytes = new byte[8];
            byte[] type = new byte[] { (byte)ContentType.Handshake }; // contenttype
            byte[] version = new byte[] { 3, 2 };
            byte[] lengthBytes = new byte[2]; 

            NumberConverter.FormatUInt64(0,seqNumBytes,0);
            NumberConverter.FormatUInt16((ushort)dataLength, lengthBytes, 0);

            readHMAC.TransformBlock(seqNumBytes, 0, 8, null, 0);
            readHMAC.TransformBlock(type, 0, 1, null, 0);
            readHMAC.TransformBlock(version, 0, 2, null, 0);
            readHMAC.TransformBlock(lengthBytes, 0, 2, null, 0);

            int hashed = 0;
            while (hashed + macLength < dataLength)
            {
                readHMAC.TransformBlock(buffer, offset + hashed, macLength, null, 0);
                hashed += macLength;
            }

            readHMAC.TransformFinalBlock(buffer, offset + hashed, dataLength - hashed);

            byte[] calculated = readHMAC.Hash;

            return true;
        }

        private byte[] GetIV(byte[] fragment)
        {
            byte[] iv = new byte[readCipher.KeySize / 8];
            Buffer.BlockCopy(fragment, 0, iv, 0, iv.Length);

            return iv;
        }

        private ReadedRecord ReadNext()
        {
            recordIO.LoadRecord();
            RecordHeader header = recordIO.RecordHeader;
            byte[] fragment = new byte[header.FragmentLength];
            recordIO.ReadFragment(fragment, 0);

            ReadedRecord readedRecord = new ReadedRecord(fragment, header);

            return readedRecord;
        }


        //Fragment format:
        //[xxencryptedx]
        //[Content][MAC]
        //
        private int ReadAsGenericStreamCipher(byte[] buffer, int offset)
        {
            ReadedRecord readedRecord = ReadNext();
            byte[] fragment = readedRecord.Fragment;

            int macLength = CryptoConst.HashSize(MacAlgorithm);
            byte[] mac = new byte[macLength];

            Buffer.BlockCopy(buffer, offset, mac, 0, macLength);
            var readDecryptor = readCipher.CreateDecryptor();

            return readDecryptor.TransformBlock(fragment, macLength, fragment.Length - macLength, buffer, offset);
        }
    }
}
