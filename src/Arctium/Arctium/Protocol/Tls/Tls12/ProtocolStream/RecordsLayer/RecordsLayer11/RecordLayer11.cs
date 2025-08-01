using System;
using Arctium.Protocol.Tls.Tls12.CryptoConfiguration;
using Arctium.Protocol.Tls.Protocol;
using System.Security.Cryptography;
using Arctium.Protocol.Tls.Protocol.RecordProtocol;
using System.IO;
using Arctium.Protocol.Tls.Protocol.BinaryOps;
using Arctium.Protocol.Tls.Tls12.Buffers;
using Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Extensions.Enum;
using Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Enum;
using Arctium.Protocol.Tls.Protocol.RecordProtocol.Enum;
using Arctium.Protocol.Tls.Tls12.CryptoConfiguration.Enum;
using Arctium.Protocol.Tls.Tls12.ProtocolStream.RecordsLayer;

namespace Arctium.Protocol.Tls.Tls12.ProtocolStream.RecordsLayer.RecordsLayer11
{
    class RecordLayer11
    {
        public LoadedFragment LoadedFragmentInfo
        {
            get
            {
                if (!LoadedDecryptedFragmentState.IsLoaded) throw new InvalidOperationException("Cannot get info because fragment is not already loaded and decrypted. Load fragent first calling 'Load()' method");
                return LoadedDecryptedFragmentState.FragmentInfo;
            }
        }

        public struct LoadedFragment
        {
            public int Length;
            public ContentType ContentType;
        }


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
                HashAlgorithmType.NULL)
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

        const int FragmentWriteLength = 2 << 14;

        SecParams11 currentSecParams;

        CipherType currentWriteCipherType;// { get { return currentSecParams.RecordCryptoType.CipherType; } }
        CipherType currentReadCipherType; // { get { return currentSecParams.RecordCryptoType.CipherType; } }
        HashAlgorithmType MacAlgorithm { get { return currentSecParams.RecordCryptoType.MACAlgorithm; } }

        byte[] BulkReadKey { get { return currentSecParams.BulkReadKey; } }
        byte[] BulkWriteKey { get { return currentSecParams.BulkWriteKey; } }
        byte[] MacReadKey { get { return currentSecParams.MacReadKey; } }
        byte[] MacWriteKey { get { return currentSecParams.MacWriteKey; } }

        HMAC readHMAC;
        HMAC writeHMAC;
        SymmetricAlgorithm readCipher;
        SymmetricAlgorithm writeCipher;

        RecordIO recordIO;

        ulong readSequenceNumber;
        ulong writeSequenceNumber;

        LoadedFragmentState LoadedDecryptedFragmentState;

        private RecordLayer11(RecordIO recordIO)
        {
            this.recordIO = recordIO;
            readSequenceNumber = 0xffffffffffffffff;
            writeSequenceNumber = 0xffffffffffffffff;

            LoadedDecryptedFragmentState = LoadedFragmentState.InitializeUnloaded();
        }

        //
        // Public Methods 
        //


        ///<summary>Creates initial state of the RecordLayerv11</summary>
        public static RecordLayer11 Initialize(RecordIO innerRecordIO)
        {
            RecordLayer11 recordLayer = new RecordLayer11(innerRecordIO);
            recordLayer.ChangeCipherSpec(InitialSecParams11);

            return recordLayer;
        }

        public LoadedFragment LoadFragment()
        {
            //fragment is already loaded. Whet fragment is loaded and this method is invoked, its do nothig (just return info about internal fragment state)
            if (LoadedDecryptedFragmentState.IsLoaded) return LoadedDecryptedFragmentState.FragmentInfo;

            switch (currentReadCipherType)
            {
                case CipherType.Stream: LoadAsGenericStreamCipher(); break;
                case CipherType.Block: LoadAsGenericBlockCipher(); break;

                default: throw new Exception("Internal error, cipher type unrecognized (should never throw), improve secparam11 validation process");
            }


            if (!LoadedDecryptedFragmentState.IsLoaded || LoadedDecryptedFragmentState.FragmentInfo.Length == 0)
            {
                throw new Exception("Internal Error. Loaded fragment but is empty or set as unloaded");
            }

            return LoadedDecryptedFragmentState.FragmentInfo;
        }

        public LoadedFragment Read(byte[] buffer, int offset)
        {
            if (!LoadedDecryptedFragmentState.IsLoaded) throw new InvalidOperationException("Cannot read fragment because is not already loaded and decrypted. Load and decrypt fragmnet first calling 'Load()'");

            byte[] toCopy = LoadedDecryptedFragmentState.DecryptedContentBuffer;
            int toCopyLength = LoadedDecryptedFragmentState.FragmentInfo.Length;
            Buffer.BlockCopy(toCopy, 0, buffer, offset, toCopyLength);

            LoadedFragment readingNow = LoadedDecryptedFragmentState.FragmentInfo;

            LoadedDecryptedFragmentState.ResetToUnloaded();
            readSequenceNumber++;

            return readingNow;
        }

        public void ChangeCipherSpec(SecParams11 newSecParams11)
        {
            currentSecParams = newSecParams11;

            readHMAC = RecordLayer11CryptoFactory.GetReadHMAC(newSecParams11);
            writeHMAC = RecordLayer11CryptoFactory.GetWriteHMAC(newSecParams11);
            readCipher = RecordLayer11CryptoFactory.GetReadCipher(newSecParams11);
            writeCipher = RecordLayer11CryptoFactory.GetWriteCipher(newSecParams11);

            readSequenceNumber = 0;
            writeSequenceNumber = 0;

            currentReadCipherType = CipherType.Stream;
            currentWriteCipherType = CipherType.Stream;
        }

        public void ChangeWriteCipherSpec(SecParams11 newSecParams11)
        {
            writeSequenceNumber = 0;
            writeHMAC = RecordLayer11CryptoFactory.GetWriteHMAC(newSecParams11);
            writeCipher = RecordLayer11CryptoFactory.GetWriteCipher(newSecParams11);
            currentWriteCipherType = newSecParams11.RecordCryptoType.CipherType;


        }

        public void ChangeReadCipherSpec(SecParams11 newSecParams11)
        {
            readSequenceNumber = 0;
            readHMAC = RecordLayer11CryptoFactory.GetReadHMAC(newSecParams11);
            readCipher = RecordLayer11CryptoFactory.GetReadCipher(newSecParams11);
            currentReadCipherType = newSecParams11.RecordCryptoType.CipherType;
        }

        public void Write(byte[] buffer, int offset, int length, ContentType contentType)
        {
            int chunkSize = 2 << 14;
            int writed = 0;

            while (writed + chunkSize < length)
            {
                switch (currentWriteCipherType)
                {
                    case CipherType.Stream: WriteAsGenericStreamCipher(buffer, offset + writed, chunkSize, contentType); break;
                    case CipherType.Block: WriteAsGenericBlockCipher(buffer, offset + writed, chunkSize, contentType); break;

                    default: throw new Exception("Internal error, cipher type unrecognized (should never throw), improve secparam11 validation process");
                }

                writed += chunkSize;
                writeSequenceNumber++;
            }

            if (length - writed > 0)
            {
                switch (currentWriteCipherType)
                {
                    case CipherType.Stream: WriteAsGenericStreamCipher(buffer, offset + writed, length - writed, contentType); break;
                    case CipherType.Block: WriteAsGenericBlockCipher(buffer, offset + writed, length - writed, contentType); break;

                    default: throw new Exception("Internal error, cipher type unrecognized (should never throw), improve secparam11 validation process");
                }

                writeSequenceNumber++;
            }

        }

        //
        // Private methods
        //

        private void WriteAsGenericBlockCipher(byte[] buffer, int offset, int length, ContentType contentType)
        {
            byte[] iv = CreateIV();
            byte[] padding = CreatePadding(length);
            byte[] hmac = ComputeWriteHMAC(buffer, offset, length, contentType);

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

            var encryptor = writeCipher.CreateEncryptor(writeCipher.Key, iv);


            byte[] encrypted = new byte[ciphertextFragment.Length];
            Array.Copy(ciphertextFragment, encrypted, ciphertextFragment.Length);

            encryptor.TransformBlock(ciphertextFragment, toEncryptOffset, toEncryptCount, encrypted, iv.Length);

            recordIO.WriteFragment(encrypted, 0, encrypted.Length, contentType);
        }

        private byte[] ComputeWriteHMAC(byte[] buffer, int offset, int length, ContentType contentType)
        {
            byte[] hmac = new byte[writeHMAC.HashSize / 8];

            //writeHMAC.Initialize();
            //writeHMAC.Key = currentSecParams.MacWriteKey;


            //int blockLength = writeHMAC. / 8;

            byte[] writeHmacPrefix = CreateHmacPrefix(writeSequenceNumber, contentType, (ushort)length);
            writeHMAC.TransformBlock(writeHmacPrefix, 0, writeHmacPrefix.Length, null, 0);

            //int hashedCountFromBuffer = 0;
            //while (hashedCountFromBuffer + blockLength < length)
            {
                //writeHMAC.TransformBlock(buffer, offset, length, null, 0);
            }
            //writeHMAC.TransformFinalBlock(buffer, hashedCountFromBuffer + offset, length - hashedCountFromBuffer);
            writeHMAC.TransformFinalBlock(buffer, offset, length);


            return writeHMAC.Hash;
        }

        private byte[] CreateHmacPrefix(ulong seqNum, ContentType contentType, ushort fragmentLength)
        {
            byte[] hashPrefix = new byte[8 + 1 + 2 + 2];
            NumberConverter.FormatUInt64(seqNum, hashPrefix, 0);
            hashPrefix[8] = (byte)contentType;
            hashPrefix[9] = 3;
            hashPrefix[10] = 2;
            NumberConverter.FormatUInt16(fragmentLength, hashPrefix, 11);

            return hashPrefix;
        }

        private byte[] CreatePadding(int length)
        {
            int blockSize = writeCipher.BlockSize / 8;
            int ivLength = writeCipher.BlockSize / 8;
            int macLength = writeHMAC.HashSize / 8;

            int totalLength = length + ivLength + macLength + 1;

            int paddingLength = blockSize - totalLength % blockSize;
            byte[] padding = new byte[paddingLength + 1];
            for (int i = 0; i < paddingLength + 1; i++)
            {
                padding[i] = (byte)paddingLength;
            }

            return padding;
        }

        private byte[] CreateIV()
        {
            int length = writeCipher.BlockSize / 8;
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

                if (remaining > 0)
                {
                    recordIO.WriteFragment(buffer, bufferSendOffset, remaining, contentType);
                }
            }
        }


        //Fragment format:
        //    [x x x ENCRYPTED x x x]
        //[IV][Content][MAC][Padding]
        //
        //[Padding] e.g. xx xx 06 06 06 06 06 06 06    (7 x 06 not 6 x 06! Last value indicates length of the padding but internally is treated as a padding)
        //  xx xx ==  last two bytes of the mac
        private void LoadAsGenericBlockCipher()
        {
            ReadedRecord record = ReadNextRecord();
            byte[] fragment = record.Fragment;

            DecryptFragmentAsBlockCipher(fragment, 0, fragment.Length);
            ThrowIfInvalidBlockCiphertextFragmentFormat(fragment, 0, fragment.Length);
            BlockFragmentOffsets offsets = CalculateBlockFragmentOffsets(fragment, 0, fragment.Length);

            byte[] receivedHmac = new byte[offsets.HmacLength];
            Buffer.BlockCopy(fragment, offsets.HmacOffset, receivedHmac, 0, offsets.HmacLength);

            byte[] computedHmac = ComputeReadHMAC(fragment, offsets.ContentOffset, offsets.ContentLength, record.RecordHeader.ContentType);

            bool hmacsEquals = BufferTools.IsContentEqual(receivedHmac, computedHmac);

            if (!hmacsEquals)
                throw new Exception("invalid HMAC");

            byte[] contentBytes = new byte[offsets.ContentLength];
            Buffer.BlockCopy(fragment, offsets.ContentOffset, contentBytes, 0, offsets.ContentLength);


            LoadedDecryptedFragmentState.SetAsLoaded(contentBytes, contentBytes.Length, record.RecordHeader.ContentType);
        }

        private void ThrowIfInvalidBlockCiphertextFragmentFormat(byte[] fragment, int offset, int length)
        {

        }

        private BlockFragmentOffsets CalculateBlockFragmentOffsets(byte[] fragment, int offset, int length)
        {
            BlockFragmentOffsets offsets = new BlockFragmentOffsets();
            offsets.IVOffset = offset;
            offsets.IVLength = readCipher.BlockSize / 8;
            offsets.PaddingLength = fragment[offset + length - 1] + 1;
            offsets.PaddingOffset = length - offsets.PaddingLength;
            offsets.HmacOffset = offsets.PaddingOffset - readHMAC.HashSize / 8;
            offsets.HmacLength = readHMAC.HashSize / 8;

            offsets.ContentLength = length - offsets.PaddingLength - offsets.HmacLength - offsets.IVLength;
            offsets.ContentOffset = offsets.HmacOffset - offsets.ContentLength;


            return offsets;
        }

        private byte[] ComputeReadHMAC(byte[] buffer, int offset, int length, ContentType contentType)
        {
            //readHMAC.Initialize();
            //readHMAC.Key = MacReadKey;
            int macLength = readHMAC.HashSize / 8;

            byte[] seqNumBytes = new byte[8];
            byte[] type = new byte[] { (byte)contentType };
            byte[] version = new byte[] { 3, 2 };
            byte[] lengthBytes = new byte[2];

            NumberConverter.FormatUInt64(readSequenceNumber, seqNumBytes, 0);
            NumberConverter.FormatUInt16((ushort)length, lengthBytes, 0);

            readHMAC.TransformBlock(seqNumBytes, 0, 8, null, 0);
            readHMAC.TransformBlock(type, 0, 1, null, 0);
            readHMAC.TransformBlock(version, 0, 2, null, 0);
            readHMAC.TransformBlock(lengthBytes, 0, 2, null, 0);

            int hashed = 0;
            while (hashed + macLength < length)
            {
                readHMAC.TransformBlock(buffer, offset + hashed, macLength, null, 0);
                hashed += macLength;
            }
            readHMAC.TransformFinalBlock(buffer, offset + hashed, length - hashed);

            byte[] calculatedHmac = readHMAC.Hash;

            return calculatedHmac;
        }

        private void DecryptFragmentAsBlockCipher(byte[] fragmentBuffer, int offset, int fragmentLength)
        {
            byte[] iv = GetIV(fragmentBuffer, offset);

            int encryptedSegmentOffset = iv.Length + offset;
            int encryptedSegmentLength = fragmentLength - iv.Length;

            var decryptor = readCipher.CreateDecryptor(readCipher.Key, iv);
            int decryptedBytesCount = decryptor.TransformBlock(fragmentBuffer, encryptedSegmentOffset, encryptedSegmentLength, fragmentBuffer, encryptedSegmentOffset);
        }

        private byte[] GetIV(byte[] fragment, int offset)
        {
            byte[] iv = new byte[readCipher.BlockSize / 8];
            Buffer.BlockCopy(fragment, offset, iv, 0, iv.Length);

            return iv;
        }

        private ReadedRecord ReadNextRecord()
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
        private void LoadAsGenericStreamCipher()
        {
            ReadedRecord readedRecord = ReadNextRecord();
            byte[] fragment = readedRecord.Fragment;

            int macLength = CryptoConst.HashSize(MacAlgorithm);
            byte[] hmac = new byte[macLength];
            byte[] decryptedContent = new byte[fragment.Length - hmac.Length];

            //Buffer.BlockCopy(buffer, offset, hmac, 0, macLength);
            var readDecryptor = readCipher.CreateDecryptor();

            readDecryptor.TransformBlock(fragment, macLength, fragment.Length - macLength, decryptedContent, 0);

            //hmac validiation

            LoadedDecryptedFragmentState.SetAsLoaded(decryptedContent, decryptedContent.Length, readedRecord.RecordHeader.ContentType);
        }
    }
}
