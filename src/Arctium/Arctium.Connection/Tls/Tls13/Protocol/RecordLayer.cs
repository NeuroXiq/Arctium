using Arctium.Connection.Tls.Tls13.API;
using Arctium.Connection.Tls.Tls13.Model;
using Arctium.Cryptography.Ciphers.BlockCiphers;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Buffers;

namespace Arctium.Connection.Tls.Tls13.Protocol
{
    class RecordLayer
    {
        const int MaxRecordContextLength = 5;
        const int MaxTlsPlaintextLength = 2 << 14;
        const int WriteBufferLength = MaxTlsPlaintextLength + 1 + 2 + 2;
        const byte LegacyVersion = 0x03;
        const ushort RecordLegacyVersion = 0x0303;

        private BufferForStream bufferForStream;
        private Validate validate;
        private RecordLayerState State;

        private byte[] buffer { get { return bufferForStream.Buffer; } }
        public byte[] RecordFragmentBytes { get; private set; }
        private byte[] plaintextReadBuffer;
        private byte[] plaintextWriteBuffer;
        private byte[] encryptedWriteBuffer;

        public ulong readSequenceNumber;
        private ulong writeSequenceNumber;
        private AEAD aeadWrite;
        private AEAD aeadRead;
        private byte[] writeIv;
        private byte[] readIv;
        private byte[] perRecordWriteNonce;
        private byte[] perRecordReadNonce;

        private bool compatibilityAllowRecordLayerVersionLower0x0303;
        private bool compatibilitySilentlyDropUnencryptedChangeCipherSpec;

        public RecordLayer(BufferForStream buffer, Validate validate)
        {
            this.bufferForStream = buffer;
            this.validate = validate;
            this.RecordFragmentBytes = new byte[MaxTlsPlaintextLength];
            this.plaintextWriteBuffer = new byte[WriteBufferLength];
            this.plaintextReadBuffer = new byte[MaxTlsPlaintextLength];
            readSequenceNumber = 0;
            writeSequenceNumber = 0;
            encryptedWriteBuffer = new byte[MaxTlsPlaintextLength];

            SetBackwardCompatibilityMode(false, false);
        }

        public void SetBackwardCompatibilityMode(
            bool compatibilityAllowRecordLayerVersionLower0x0303 = false,
            bool compatibilitySilentlyDropUnencryptedChangeCipherSpec = false)
        {
            this.compatibilityAllowRecordLayerVersionLower0x0303 = compatibilityAllowRecordLayerVersionLower0x0303;
            this.compatibilitySilentlyDropUnencryptedChangeCipherSpec = compatibilitySilentlyDropUnencryptedChangeCipherSpec;
        }


        public void SetState(RecordLayerState state)
        {
            this.State = state;
        }

        public RecordInfo Read(bool isInitialClientHello = false)
        {
            int firstThreeFields = 5;
            ContentType contentType;
            ushort version;
            ushort length;
            RecordInfo recordInfo;

            bufferForStream.LoadToLength(firstThreeFields);

            byte contentTypeByte = (byte)buffer[0];
            contentType = (ContentType)contentTypeByte;
            version = (ushort)((buffer[1] << 8) | (buffer[2] << 0));
            length = (ushort)((buffer[3] << 8) | (buffer[4] << 0));

            if (contentType == ContentType.ChangeCipherSpec && compatibilitySilentlyDropUnencryptedChangeCipherSpec)
            {
                // load this record and do totally drop it as not exists
                // this method was invoked, so anyway other record is expected, return next one
                bufferForStream.LoadToLength(firstThreeFields + length);
                bufferForStream.TrimStart(5 + length);

                return Read();
            }

            validate.RecordLayer.ValidateContentType(contentTypeByte);
            validate.RecordLayer.ProtocolVersion(version, compatibilityAllowRecordLayerVersionLower0x0303);
            validate.RecordLayer.Length(length);
            
            bufferForStream.LoadToLength(firstThreeFields + length);

            if (aeadWrite != null && contentType == ContentType.ApplicationData)
            {
                // readSequenceNumber = 0;
                ComputeReadNonce();
                int authTagLen = aeadRead.AuthenticationTagLengthBytes;
                int encryptedDataLen = length - authTagLen;
                int authTagOffset = encryptedDataLen + 5;

                bool isAeadTagValid;

                aeadRead.AuthenticatedDecryption(
                    perRecordReadNonce, 0, perRecordReadNonce.Length,
                    bufferForStream.Buffer, 5, encryptedDataLen,
                    bufferForStream.Buffer, 0, 5,
                    RecordFragmentBytes, 0,
                    bufferForStream.Buffer, authTagOffset,
                    out isAeadTagValid);

                validate.RecordLayer.AEADAuthTagInvalid(isAeadTagValid);

                recordInfo = new RecordInfo((ContentType)RecordFragmentBytes[encryptedDataLen - 1], version, encryptedDataLen - 1);
            }
            else
            {
                MemCpy.Copy(buffer, firstThreeFields, RecordFragmentBytes, 0, length);
                recordInfo = new RecordInfo(contentType, version, length);
            }

            int recordLen = 5 + length;
            bufferForStream.TrimStart(recordLen);

            readSequenceNumber++;

            return recordInfo;
        }

        public void Write(ContentType contentType, byte[] buffer, long offset, long length)
        {
            int chunkLen = MaxTlsPlaintextLength; // MaxRecordContextLength;
            // int chunks = (int)(length + chunkLen) / chunkLen;
            long remToWrite = length;
            long start = offset;

            while (remToWrite > 0)
            {
                // ushort len = (ushort)(length - (i * chunkLen) + 1);
                // long len = ((i + 1) * chunkLen <= length) ? chunkLen : (length - (i * chunkLen));

                long len = remToWrite - chunkLen >= 0 ? chunkLen : remToWrite;

               WriteSingleRecord(contentType, buffer, start, (ushort)len);

                remToWrite -= len;
                start += len;
            }
        }

        void WriteSingleRecord(ContentType type, byte[] buffer, long offset, ushort length)
        {
            if (aeadWrite != null)
            {
                // encrypteddatalen + contentType (1 byte)
                int encryptedLength = this.aeadWrite.AuthenticationTagLengthBytes + length + 1;
                int toEncryptLen = length + 1;
                int toSendLength = encryptedLength + 5;

                MemCpy.Copy(buffer, offset, plaintextWriteBuffer, 0, length);
                plaintextWriteBuffer[length] = (byte)type;

                encryptedWriteBuffer[0] = (byte)(ContentType.ApplicationData);
                encryptedWriteBuffer[1] = encryptedWriteBuffer[2] = LegacyVersion;
                MemMap.ToBytes1UShortBE((ushort)encryptedLength, encryptedWriteBuffer, 3);

                ComputeWriteNonce();

                aeadWrite.AuthenticatedEncryption(
                    perRecordWriteNonce, 0, perRecordWriteNonce.Length,
                    plaintextWriteBuffer, 0, toEncryptLen,
                    encryptedWriteBuffer, 0, 5,
                    encryptedWriteBuffer, 5,
                    encryptedWriteBuffer, toEncryptLen + 5);

                bufferForStream.Write(encryptedWriteBuffer, 0, toSendLength);
            }
            else
            {
                int bytesLen = 5 + length;
                plaintextWriteBuffer[0] = (byte)type;
                plaintextWriteBuffer[1] = plaintextWriteBuffer[2] = LegacyVersion;
                MemMap.ToBytes1UShortBE(length, plaintextWriteBuffer, 3);

                MemCpy.Copy(buffer, offset, plaintextWriteBuffer, 5, length);
                bufferForStream.Write(plaintextWriteBuffer, 0, bytesLen);
            }

            writeSequenceNumber++;
        }

        public void ChangeCipher(AEAD aeadWrite, AEAD aeadRead, byte[] writeIv, byte[] readIv)
        {
            writeSequenceNumber = readSequenceNumber = 0;
            this.aeadWrite = aeadWrite;
            this.aeadRead = aeadRead;
            this.writeIv = writeIv;
            this.readIv = readIv;
            this.perRecordReadNonce = new byte[writeIv.Length];
            this.perRecordWriteNonce = new byte[writeIv.Length];
            this.State = RecordLayerState.EncryptionOn;
        }

        void ComputeWriteNonce() => ComputeNonce(perRecordWriteNonce, writeSequenceNumber, writeIv);
        void ComputeReadNonce() => ComputeNonce(perRecordReadNonce, readSequenceNumber, readIv);

        void ComputeNonce(byte[] resultNonce, ulong sequenceNumber, byte[] iv)
        {
            MemOps.MemsetZero(resultNonce);
            MemMap.ToBytes1ULongBE(sequenceNumber, resultNonce, resultNonce.Length - 8);

            for (int i = 0; i < iv.Length; i++) resultNonce[i] = (byte)(resultNonce[i] ^ iv[i]);
        }

        public struct RecordInfo
        {
            public ContentType ContentType;
            ushort ProtocolVersion;
            public int Length;

            public RecordInfo(ContentType contentType, ushort protocolVersion, int length)
            {
                ContentType = contentType;
                ProtocolVersion = protocolVersion;
                Length = length;
            }
        }
    }
}
