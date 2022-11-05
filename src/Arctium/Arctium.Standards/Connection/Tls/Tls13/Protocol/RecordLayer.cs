using Arctium.Standards.Connection.Tls.Tls13.API;
using Arctium.Standards.Connection.Tls.Tls13.Model;
using Arctium.Cryptography.Ciphers.BlockCiphers;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Buffers;
using System.Net.Sockets;
using System;
using Arctium.Shared.Other;

namespace Arctium.Standards.Connection.Tls.Tls13.Protocol
{
    class RecordLayer
    {
        const int RecordHeaderBytesCount = 5;
        const int MaxTlsPlaintextLength = 1 << 14;
        const int WriteBufferLength = MaxTlsPlaintextLength + 1 + 2 + 2;
        const byte LegacyVersion = 0x03;

        const int EncryptedRecordMaxContentLength = (1 << 14) + 256;
        
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
        private ushort configuredMaxPlaintextRecordLength;

        private bool compatibilityAllowRecordLayerVersionLower0x0303;
        private bool compatibilitySilentlyDropUnencryptedChangeCipherSpec;

        public RecordLayer(BufferForStream buffer, Validate validate)
        {
            this.configuredMaxPlaintextRecordLength = Tls13Const.RecordLayer_MaxPlaintextApplicationDataLength;
            this.bufferForStream = buffer;
            this.validate = validate;
            this.RecordFragmentBytes = new byte[WriteBufferLength];
            this.plaintextWriteBuffer = new byte[WriteBufferLength];
            this.plaintextReadBuffer = new byte[MaxTlsPlaintextLength];
            readSequenceNumber = 0;
            writeSequenceNumber = 0;

            encryptedWriteBuffer = new byte[EncryptedRecordMaxContentLength + RecordHeaderBytesCount];
            State = RecordLayerState.EncryptionOff;

            SetBackwardCompatibilityMode(false, false);
        }

        public void SetBackwardCompatibilityMode(
            bool compatibilityAllowRecordLayerVersionLower0x0303 = false,
            bool compatibilitySilentlyDropUnencryptedChangeCipherSpec = false)
        {
            this.compatibilityAllowRecordLayerVersionLower0x0303 = compatibilityAllowRecordLayerVersionLower0x0303;
            this.compatibilitySilentlyDropUnencryptedChangeCipherSpec = compatibilitySilentlyDropUnencryptedChangeCipherSpec;
        }

        public RecordInfo Read()
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

            validate.RecordLayer.ValidateRecord(
                    State == RecordLayerState.EncryptionOn,
                    length,
                    (byte)contentType,
                    version,
                    configuredMaxPlaintextRecordLength,
                    compatibilityAllowRecordLayerVersionLower0x0303);

            if (contentType == ContentType.ChangeCipherSpec && compatibilitySilentlyDropUnencryptedChangeCipherSpec)
            {
                // load this record and do totally drop it as not ever exists
                // this method was invoked, so anyway other record is expected, return next one
                // this is trick because of compatibility
                bufferForStream.LoadToLength(firstThreeFields + length);
                bufferForStream.TrimStart(5 + length);

                return Read();
            }
            
            bufferForStream.LoadToLength(firstThreeFields + length);

            if (aeadWrite != null && contentType == ContentType.ApplicationData)
            {
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

                int plaintextDataLength = encryptedDataLen - 1;
                var plaintextContentType = RecordFragmentBytes[encryptedDataLen - 1];

                validate.RecordLayer.AEADAuthTagInvalid(isAeadTagValid);
                validate.RecordLayer.ValidateRecord(false,
                    (ushort)plaintextDataLength,
                    plaintextContentType,
                    version,
                    configuredMaxPlaintextRecordLength,
                    compatibilityAllowRecordLayerVersionLower0x0303);

                recordInfo = new RecordInfo((ContentType)plaintextContentType, version, plaintextDataLength);
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
            int chunkLen = configuredMaxPlaintextRecordLength;
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

        internal void SetRecordSizeLimit(ushort maxRecord)
        {
            Validation.ThrowInternal(maxRecord > Tls13Const.RecordLayer_MaxPlaintextApplicationDataLength);
            this.configuredMaxPlaintextRecordLength = maxRecord;
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

        public void ChangeWriteEncryption(AEAD newWrite, byte[] newIv)
        {
            this.perRecordWriteNonce = new byte[newIv.Length];
            writeSequenceNumber = 0;
            this.writeIv = newIv;
            this.aeadWrite = newWrite;
        }

        public void ChangeReadEncryption(AEAD newRead, byte[] newIv)
        {
            this.perRecordReadNonce = new byte[newIv.Length];
            readSequenceNumber = 0;
            this.readIv = newIv;
            this.aeadRead = newRead;
        }
    }
}
