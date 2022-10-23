using Arctium.Standards.Connection.Tls.Tls13.Model;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Buffers;
using System.IO;
using System;
using Arctium.Shared.Other;

namespace Arctium.Standards.Connection.Tls.Tls13.Protocol
{
    internal class MessageIO
    {
        public delegate void ReadWriteCallback(byte[] buffer, int offset, int length);
        public event ReadWriteCallback OnHandshakeReadWrite;

        public RecordLayer recordLayer;
        private ByteBuffer byteBuffer;
        private Validate validate;
        private ModelDeserialization clientModelDeserialization;
        private ModelSerialization modelSerialization;
        // private List<KeyValuePair<HandshakeType, byte[]>> handshakeContext;

        private byte[] buffer { get { return byteBuffer.Buffer; } }
        private int currentMessageLength;
        private RecordLayer.RecordInfo lastLoadedRecord;


        public MessageIO(Stream networkStream,
            Validate validate)
        {
            this.recordLayer = new RecordLayer(new BufferForStream(networkStream), validate);

            modelSerialization = new ModelSerialization();
            
            this.lastLoadedRecord = new RecordLayer.RecordInfo(ContentType.Invalid, 0, -1);

            this.byteBuffer = new ByteBuffer();
            this.validate = validate;
            this.clientModelDeserialization = new ModelDeserialization(validate);
        }

        public void SetBackwardCompatibilityMode(
            bool compatibilityAllowRecordLayerVersionLower0x0303 = false,
            bool compatibilitySilentlyDropUnencryptedChangeCipherSpec = false)
        {
            recordLayer.SetBackwardCompatibilityMode(
                compatibilityAllowRecordLayerVersionLower0x0303: compatibilityAllowRecordLayerVersionLower0x0303,
                compatibilitySilentlyDropUnencryptedChangeCipherSpec: compatibilitySilentlyDropUnencryptedChangeCipherSpec);
        }

        public bool TryLoadApplicationData(byte[] outBuffer, long outOffs, out int applicationDataLength)
        {
            RecordLayer.RecordInfo info;
            applicationDataLength = -1;

            if (byteBuffer.DataLength == 0)
            {
                info = LoadRecord();
            }
            else
            {
                info = lastLoadedRecord;
            }

            if (info.ContentType == ContentType.ApplicationData)
            {
                MemCpy.Copy(buffer, 0, outBuffer, outOffs, info.Length);
                applicationDataLength = info.Length;

                byteBuffer.TrimStart(info.Length);

                return true;
            }

            return false;
        }

        public void WriteApplicationData(byte[] buffer, long offset, long length)
        {
            recordLayer.Write(ContentType.ApplicationData, buffer, offset, length);
        }

        public void WriteHandshake(object handshakeMsg)
        {
            modelSerialization.Reset();

            modelSerialization.ToBytes(handshakeMsg);

            var type = (HandshakeType)(modelSerialization.SerializedData[0]);

            HandshakeContextAdd(type, modelSerialization.SerializedData, 0, modelSerialization.SerializedDataLength);
            // handshakeContext.Add(
            //     new KeyValuePair<HandshakeType, byte[]>(type,
            //     MemCpy.CopyToNewArray(modelSerialization.SerializedData, 0, modelSerialization.SerializedDataLength)));

            recordLayer.Write(ContentType.Handshake, modelSerialization.SerializedData, 0, modelSerialization.SerializedDataLength);
        }

        public HandshakeType LoadHandshakeMessage()
        {
            LoadHandshake();

            return (HandshakeType)buffer[0];
        }

        public T ReadHandshakeMessage<T>()
        {
            HandshakeType type = LoadHandshakeMessage();

            object result = clientModelDeserialization.Deserialize<T>(buffer, 0);

            int len = (buffer[1] << 16) | (buffer[2] << 8) | (buffer[3]);

            HandshakeContextAdd(type, buffer, 0, len + 4);

            byteBuffer.TrimStart(len + 4);
            MemOps.MemsetZero(byteBuffer.Buffer, byteBuffer.DataLength, byteBuffer.Buffer.Length - byteBuffer.DataLength);

            return (T)result;
        }

        //public void LoadCertificateMessage(CertificateType type)
        //{
        //    throw new Exception("need to add to context");
        //    LoadHandshake();
        //    clientModelDeserialization.DeserializeCertificate(buffer, 0, type);

        //    int len = (buffer[1] << 16) | (buffer[2] << 8) | (buffer[3]);

        //    // handshakeContext.Add(MemCpy.CopyToNewArray(byteBuffer.Buffer, 0, len + 4));

        //    // HandshakeContextAdd(HandshakeType.Certificate, MemCpy.CopyToNewArray(byteBuffer.Buffer, 0, len + 4));
        //    HandshakeContextAdd(HandshakeType.Certificate, byteBuffer.Buffer, 0, len);

        //    byteBuffer.TrimStart(len + 4);
        //}

        void HandshakeContextAdd(HandshakeType type, byte[] buffer, long offset, long length) => OnHandshakeReadWrite?.Invoke(buffer, (int)offset, (int)length);

        // void HandshakeContextAdd(HandshakeType type, byte[] rawMessageBytes) => this.handshakeContext.Add(new KeyValuePair<HandshakeType, byte[]>(type, rawMessageBytes));

        internal void ChangeRecordLayerCrypto(Crypto crypto, Crypto.RecordLayerKeyType keyType) => crypto.ChangeRecordLayerCrypto(recordLayer, keyType);

        private void LoadHandshake()
        {
            while (byteBuffer.DataLength < 4)
            {
                var recordInfo = LoadRecord();
                validate.Handshake.RecordTypeIsHandshareAndNotInterleavedWithOtherRecordTypes(recordInfo.ContentType);
            }

            HandshakeType handshakeType = (HandshakeType)buffer[0];
            int msgLength = (buffer[1] << 16) | (buffer[2] << 08) | (buffer[3] << 00);

            validate.Handshake.ValidHandshakeType(handshakeType);

            while (byteBuffer.DataLength < 4 + msgLength)
            {
                LoadRecord();
            }

            currentMessageLength = msgLength;
        }

        private RecordLayer.RecordInfo LoadRecord()
        {
            RecordLayer.RecordInfo recordInfo = recordLayer.Read();
            validate.Handshake.NotZeroLengthFragmentsOfHandshake(recordInfo.Length);

            // if (recordInfo.ContentType == ContentType.Alert) Console.WriteLine(((AlertDescription)recordLayer.RecordFragmentBytes[1]).ToString());

            if (recordInfo.ContentType == ContentType.Alert)
            {
                AlertDescription description = (AlertDescription)recordLayer.RecordFragmentBytes[1];
                AlertLevel level = (AlertLevel)recordLayer.RecordFragmentBytes[0];

                string alertFormat = string.Format("Received: Alert Level: {0}, Alert Description: {1} (raw values: level: {2}, description: {3})",
                    level.ToString(), description.ToString(), (int)level, (int)description);

                validate.RecordLayer.Throw(true, alertFormat);
            } 

            byteBuffer.Append(recordLayer.RecordFragmentBytes, 0, recordInfo.Length);
            return recordInfo;
        }

        internal void SetRecordSizeLimit(ushort value)
        {
            recordLayer.SetRecordSizeLimit(value);
        }
    }
}
