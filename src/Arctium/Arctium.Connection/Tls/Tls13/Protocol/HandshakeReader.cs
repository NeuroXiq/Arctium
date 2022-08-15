using Arctium.Connection.Tls.Tls13.Model;
using Arctium.Connection.Tls.Tls13.Model.Extensions;
using Arctium.Shared.Helpers.Buffers;
using System.Collections.Generic;

namespace Arctium.Connection.Tls.Tls13.Protocol
{
    internal class HandshakeReader
    {
        private RecordLayer recordLayer;
        private ByteBuffer byteBuffer;
        private Validate validate;
        private ModelDeserialization modelSerialization;

        private byte[] buffer { get { return byteBuffer.Buffer; } }
        private int currentMessageLength;

        public HandshakeReader(RecordLayer recordLayer, Validate validate)
        {
            this.recordLayer = recordLayer;
            this.byteBuffer = new ByteBuffer();
            this.validate = validate;
            this.modelSerialization = new ModelDeserialization(validate);
        }

        public ClientHello ReadClientHello()
        {
            int startOffset = 4;
            int cursor = startOffset;
            int versionOffs = 4;
            int randomOffs = versionOffs + 2;
            int legSessIdOffs = randomOffs + 32;
            int ciphSuitOffs = -1;
            int legCompMethOffs = -1;
            int extOffs = -1;
            int legacySessIdLen = -1;
            int ciphSuiteLen = -1;
            int legComprLen = -1;
            int extLen = -1;

            byte[] random = new byte[32];
            byte[] legacySessId = null;
            byte[] legComprMeth = null;

            int minMsgLen = 2 + 32 + 1 + 2 + 1 + 2;

            LoadHandshake(HandshakeType.ClientHello, true);
            ThrowIfExceedLength(minMsgLen - 1);

            //AppendMinimum(minMsgLen, true);

            ClientHello msg = new ClientHello();

            ushort protocolVerson = MemMap.ToUShort2BytesBE(buffer, cursor);
            cursor += 2;
            MemCpy.Copy(buffer, cursor, random, 0, 32);
            cursor += 32;
            legacySessIdLen = (int)buffer[cursor];
            legacySessId = new byte[legacySessIdLen];
            cursor += 1;

            ThrowIfExceedLength(cursor + legacySessIdLen - 1);
            MemCpy.Copy(buffer, cursor, legacySessId, 0, legacySessIdLen);
            cursor += legacySessIdLen;

            //LoadToLength(ciphSuitOffs + 1 + 2);
            ThrowIfExceedLength(cursor + 1);
            ciphSuiteLen = MemMap.ToUShort2BytesBE(buffer, cursor);
            validate.Handshake.ClientHello_CipherSuiteLength(ciphSuiteLen);
            // cipherSuites = new byte[ciphSuiteLen];
            
            cursor += 2;
            ThrowIfExceedLength(cursor + ciphSuiteLen - 1);
            
            //MemCpy.Copy(buffer, cursor, cipherSuites, 0, ciphSuiteLen);

            CipherSuite[] cipherSuites = new CipherSuite[ciphSuiteLen / 2];
            for (int i = 0; i < ciphSuiteLen; i += 2) cipherSuites[i / 2] = (CipherSuite)MemMap.ToUShort2BytesBE(buffer, cursor + i);

            cursor += ciphSuiteLen;

            //LoadToLength((legCompMethOffs + 1) + 1);
            ThrowIfExceedLength(cursor + 1);
            legComprLen = buffer[cursor];
            cursor += 1;
            legComprMeth = new byte[legComprLen];
            ThrowIfExceedLength(cursor + legComprLen - 1);
            MemCpy.Copy(buffer, cursor, legComprMeth, 0, legComprLen);
            cursor += legComprLen;

            // Extensions
            //LoadToLength((legCompMethOffs + legComprLen + 1) + 2);
            extLen = MemMap.ToUShort2BytesBE(buffer, cursor);
            cursor += 2;
            ThrowIfExceedLength(cursor + extLen - 1);
            Extension[] extensions = DeserializeExtensions(buffer, cursor - 2);

            //LoadToLength(extOffs + 1 + 2 + extLen);
            cursor += extLen;

            msg.ProtocolVersion = protocolVerson;
            msg.Random = random;
            msg.LegacySessionId = legacySessId;
            msg.CipherSuites = cipherSuites;
            msg.LegacyCompressionMethods = legComprMeth;
            msg.Extensions = extensions;

            validate.Handshake.ClientHello_ClientHello(msg);

            return msg;
        }

        private Extension[] DeserializeExtensions(byte[] buffer, int offset)
        {
            int cursor = offset;
            int extLen = MemMap.ToUShort2BytesBE(buffer, cursor);
            int end = offset + extLen + 2;
            int maxLength = extLen;
            cursor += 2;

            if (extLen != 0 && extLen < 8)
                validate.Handshake.ThrowGeneral("length of extensions is less that 4 and larger than 0. Min length of extensions is 8");

            List<Extension> extensions = new List<Extension>();

            while (cursor < end)
            {
                ModelDeserialization.ExtensionDeserializeResult result = modelSerialization.DeserializeExtension(buffer, cursor, extLen, true);

                maxLength -= result.Length;
                cursor += result.Length;

                if (result.IsRecognized)
                {
                    extensions.Add(result.Extension);
                }
            }

            if (cursor != end)
                validate.Extensions.ThrowGeneralException("Invalid length of some of extensions." +
                    "Total leght of all extensions computed separated (for each exension in the list ) " +
                    "doesnt match length of the list (in bytes, of clienthello field)");

            return extensions.ToArray();
        }


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

        private void LoadHandshake(HandshakeType expectedType ,bool isInitialClientHello = false)
        {
            while (byteBuffer.DataLength < 4)
            {
                LoadRecord(isInitialClientHello);
            }

            HandshakeType handshakeType = (HandshakeType)buffer[0];
            int msgLength = (buffer[1] << 16) | (buffer[2] << 08) | (buffer[3] << 00);

            validate.Handshake.ValidHandshakeType(handshakeType);
            validate.Handshake.ExpectedOrderOfHandshakeType(expectedType, handshakeType);

            while (byteBuffer.DataLength < 4 + msgLength)
            {
                recordLayer.Read();
            }

            currentMessageLength = msgLength;
        }

        private void LoadRecord(bool isInitialClientHello = false)
        {
            RecordLayer.RecordInfo recordInfo = recordLayer.Read(isInitialClientHello);
            validate.Handshake.NotZeroLengthFragmentsOfHandshake(recordInfo.Length);
            validate.Handshake.RecordTypeIsHandshareAndNotInterleavedWithOtherRecordTypes(recordInfo.ContentType);

            byteBuffer.Append(recordLayer.RecordFragmentBytes, 0, recordInfo.Length);
        }   
    }
}
