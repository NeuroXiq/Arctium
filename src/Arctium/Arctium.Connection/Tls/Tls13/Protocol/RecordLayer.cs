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

        private BufferForStream bufferForStream;
        private Validate validate;

        private byte[] buffer { get { return bufferForStream.Buffer; } }
        public byte[] RecordFragmentBytes { get; private set; }
        public byte[] EncryptedRecordFragmentBytes { get; private set; }
        private byte[] plaintextWriteBuffer;
        private byte[] encryptedWriteBuffer;

        private ulong readSequenceNumber;
        private ulong writeSequenceNumber;
        private AEAD aeadWrite;
        private AEAD aeadRead;
        private byte[] writeIv;
        private byte[] readIv;
        private byte[] perRecordWriteNonce;
        private byte[] perRecordReadNonce;

        public RecordLayer(BufferForStream buffer, Validate validate)
        {
            this.bufferForStream = buffer;
            this.validate = validate;
            this.RecordFragmentBytes = new byte[MaxTlsPlaintextLength];
            this.plaintextWriteBuffer = new byte[WriteBufferLength];
            readSequenceNumber = 0;
            writeSequenceNumber = 0;
            encryptedWriteBuffer = new byte[MaxTlsPlaintextLength];
        }

        public RecordInfo Read(bool isInitialClientHello = false)
        {
            int firstThreeFields = 5;
            ContentType contentType;
            ushort version;
            ushort length;

            bufferForStream.LoadToLength(firstThreeFields);

            byte contentTypeByte = (byte)buffer[0];
            version = (ushort)((buffer[1] << 8) | (buffer[2] << 0));
            length = (ushort)((buffer[3] << 8) | (buffer[4] << 0));

            validate.RecordLayer.ValidateContentType(contentTypeByte);
            validate.RecordLayer.ProtocolVersion(version, isInitialClientHello);
            validate.RecordLayer.Length(length);

            contentType = (ContentType)contentTypeByte;

            bufferForStream.LoadToLength(firstThreeFields + length);

            MemCpy.Copy(buffer, firstThreeFields, RecordFragmentBytes, 0, length);

            int recordLen = 5 + length;
            bufferForStream.TrimStart(recordLen);

            readSequenceNumber++;

            return new RecordInfo(contentType, version, length);
        }

        public void Write(ContentType contentType, byte[] buffer, long offset, long length)
        {
            int chunkLen = MaxRecordContextLength;
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
            plaintextWriteBuffer[0] = (byte)type;
            plaintextWriteBuffer[1] = plaintextWriteBuffer[2] = LegacyVersion;
            MemMap.ToBytes1UShortBE(length, plaintextWriteBuffer, 3);
            MemCpy.Copy(buffer, offset, plaintextWriteBuffer, 5, length);

            int bytesLen = 5 + length;

            if (aeadWrite != null)
            {
                int encryptedLength = this.aeadWrite.AuthenticationTagLengthBytes + length + 5;
                int toSendLength = encryptedLength + 5;

                encryptedWriteBuffer[0] = (byte)(ContentType.ApplicationData);
                encryptedWriteBuffer[1] = encryptedWriteBuffer[2] = LegacyVersion;
                MemMap.ToBytes1UShortBE((ushort)encryptedLength, encryptedWriteBuffer, 3);

                ComputeWriteNonce();

                aeadWrite.AuthenticatedEncryption(
                    perRecordWriteNonce, 0, perRecordWriteNonce.Length,
                    plaintextWriteBuffer, 0, length + 5,
                    encryptedWriteBuffer, 0, 5,
                    encryptedWriteBuffer, 5, encryptedWriteBuffer, length + 5);

                bufferForStream.Write(encryptedWriteBuffer, 0, toSendLength);
            }
            else
            {
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
        }

        void ComputeWriteNonce()
        {
            MemOps.MemsetZero(perRecordWriteNonce);
            MemMap.ToBytes1ULongBE(writeSequenceNumber, perRecordWriteNonce, perRecordWriteNonce.Length - 8);

            for (int i = 0; i < writeIv.Length; i++) perRecordWriteNonce[i] = (byte)(perRecordWriteNonce[i] ^ writeIv[i]);
        }

        void ComputeReadNonce()
        {
            
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
