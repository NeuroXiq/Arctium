using Arctium.Connection.Tls.Tls13.Model;
using Arctium.Connection.Tls.Tls13.Model.Extensions;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Buffers;
using System;
using System.Collections.Generic;
using System.IO;

namespace Arctium.Connection.Tls.Tls13.Protocol
{
    internal class MessageIO
    {
        private MessageIOState State;
        private RecordLayer recordLayer;
        private ByteBuffer byteBuffer;
        private Validate validate;
        private ModelDeserialization serverModelDeserialization;
        private ModelDeserialization clientModelDeserialization;
        private List<KeyValuePair<HandshakeType, byte[]>> handshakeContext;

        private byte[] buffer { get { return byteBuffer.Buffer; } }
        private int currentMessageLength;

        public MessageIO(Stream networkStream, Validate validate, List<KeyValuePair<HandshakeType, byte[]>> handshakeContext)
        {
            this.recordLayer = new RecordLayer(new BufferForStream(networkStream), validate);

            // this.recordLayer = recordLayer;
            
            this.byteBuffer = new ByteBuffer();
            this.validate = validate;
            this.serverModelDeserialization = new ModelDeserialization(validate);
            this.clientModelDeserialization = new ModelDeserialization(validate);
            this.handshakeContext = handshakeContext;
            this.State = MessageIOState.FirstClientHello;
        }

        public void SetState(MessageIOState state)
        {
            State = state;
        }

        public void WriteHandshake(object handshakeMsg)
        {

        }

        public T LoadHandshakeMessage<T>(bool isInitialClientHello = false)
        {
            int loaded = 0;

            LoadHandshake(isInitialClientHello);

            int constHandshakeFieldsCount = 4;

            HandshakeType type = (HandshakeType)buffer[0];

            object result = clientModelDeserialization.Deserialize<T>(buffer, 0);

            //switch (type)
            //{
            //    case HandshakeType.ClientHello:
            //        result = clientModelDeserialization.Deserialize<ClientHello>(buffer, 0);
            //        break;
            //    case HandshakeType.ServerHello:
            //        result = clientModelDeserialization.Deserialize<ServerHello>(buffer, 0);
            //        break;
            //    case HandshakeType.EncryptedExtensions:
            //        result = clientModelDeserialization.Deserialize<EncryptedExtensions>(buffer, 0);
            //        break;
            //    case HandshakeType.CertificateVerify:
            //        result = clientModelDeserialization.Deserialize<CertificateVerify>(buffer, 0);
            //        break;
            //    case HandshakeType.Finished:
            //        result = clientModelDeserialization.Deserialize<Finished>(buffer, 0);
            //        break;
            //    default: throw new System.Exception($"unknow handshake type {type.ToString()}");  break;
            //}

            int len = (buffer[1] << 16) | (buffer[2] << 8) | (buffer[3]);

            // handshakeContext.Add(MemCpy.CopyToNewArray(byteBuffer.Buffer, 0, len + 4));
            HandshakeContextAdd(type, MemCpy.CopyToNewArray(byteBuffer.Buffer, 0, len + 4));

            byteBuffer.TrimStart(len + 4);
            MemOps.MemsetZero(byteBuffer.Buffer, byteBuffer.DataLength, byteBuffer.Buffer.Length - byteBuffer.DataLength);

            return (T)result;
        }

        public void LoadCertificateMessage(CertificateType type)
        {
            LoadHandshake(true);
            clientModelDeserialization.DeserializeCertificate(buffer, 0, type);

            int len = (buffer[1] << 16) | (buffer[2] << 8) | (buffer[3]);

            // handshakeContext.Add(MemCpy.CopyToNewArray(byteBuffer.Buffer, 0, len + 4));

            HandshakeContextAdd(HandshakeType.Certificate, MemCpy.CopyToNewArray(byteBuffer.Buffer, 0, len + 4));

            byteBuffer.TrimStart(len + 4);
        }

        void HandshakeContextAdd(HandshakeType type, byte[] rawMessageBytes) => this.handshakeContext.Add(new KeyValuePair<HandshakeType, byte[]>(type, rawMessageBytes));

        //private Extension[] DeserializeExtensions(byte[] buffer, int offset)
        //{
        //    int cursor = offset;
        //    int extLen = MemMap.ToUShort2BytesBE(buffer, cursor);
        //    int end = offset + extLen + 2;
        //    int maxLength = extLen;
        //    cursor += 2;

        //    if (extLen != 0 && extLen < 8)
        //        validate.Handshake.ThrowGeneral("length of extensions is less that 4 and larger than 0. Min length of extensions is 8");

        //    List<Extension> extensions = new List<Extension>();

        //    while (cursor < end)
        //    {
        //        ModelDeserialization.ExtensionDeserializeResult result = serverModelDeserialization.DeserializeExtension(Endpoint.Server, buffer, new RangeCursor(cursor, cursor + end - 1));

        //        maxLength -= result.Length;
        //        cursor += result.Length;

        //        if (result.IsRecognized)
        //        {
        //            extensions.Add(result.Extension);
        //        }
        //    }

        //    if (cursor != end)
        //        validate.Extensions.ThrowGeneralException("Invalid length of some of extensions." +
        //            "Total leght of all extensions computed separated (for each exension in the list ) " +
        //            "doesnt match length of the list (in bytes, of clienthello field)");

        //    return extensions.ToArray();
        //}


        //private void AppendMinimum(int length, bool isInitialClientHello = false)
        //{
        //    int appended = 0;

        //    do
        //    {
        //        RecordLayer.RecordInfo record = LoadHandshake(isInitialClientHello);

        //        byteBuffer.Append(recordLayer.RecordFragmentBytes, 0, record.Length);
        //        appended += record.Length;

        //    } while (appended < length);
        //}

        //private void LoadToLength(int length)
        //{
        //    if (byteBuffer.DataLength >= length) return;

        //    int remaining = byteBuffer.DataLength - length;

        //    do
        //    {
        //        RecordLayer.RecordInfo record = LoadHandshake();
        //        byteBuffer.Append(recordLayer.RecordFragmentBytes, 0, record.Length);
        //        remaining -= record.Length;

        //    } while (remaining > 0);
        //}

        private void ThrowIfExceedLength(int expectedMaxPosition)
        {
            if (expectedMaxPosition >= currentMessageLength + 4)
            {
                validate.Handshake.ThrowGeneral("Invalid length of fileds. Some length doesn't match with length expected by leght field in Handshake message");
            }       

        }

        private void LoadHandshake(bool isInitialClientHello = false)
        {
            while (byteBuffer.DataLength < 4)
            {
                LoadRecord(isInitialClientHello);
            }

            HandshakeType handshakeType = (HandshakeType)buffer[0];
            int msgLength = (buffer[1] << 16) | (buffer[2] << 08) | (buffer[3] << 00);

            validate.Handshake.ValidHandshakeType(handshakeType);
            // validate.Handshake.ExpectedOrderOfHandshakeType(expectedType, handshakeType);

            while (byteBuffer.DataLength < 4 + msgLength)
            {
                LoadRecord(isInitialClientHello);
            }

            currentMessageLength = msgLength;
        }

        private void LoadRecord(bool isInitialClientHello = false)
        {
            RecordLayer.RecordInfo recordInfo = recordLayer.Read(isInitialClientHello);
            validate.Handshake.NotZeroLengthFragmentsOfHandshake(recordInfo.Length);
            validate.Handshake.RecordTypeIsHandshareAndNotInterleavedWithOtherRecordTypes(recordInfo.ContentType);

            if (recordInfo.ContentType == ContentType.Alert) throw new Exception("alert: " + ((AlertDescription)recordLayer.RecordFragmentBytes[0]).ToString());
            if (recordInfo.ContentType == ContentType.ChangeCipherSpec)
                return;

            byteBuffer.Append(recordLayer.RecordFragmentBytes, 0, recordInfo.Length);
        }   
    }
}
