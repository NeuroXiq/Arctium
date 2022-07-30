using Arctium.Connection.Tls.Tls13.Model;
using Arctium.Shared.Helpers.Buffers;

namespace Arctium.Connection.Tls.Tls13.Protocol
{
    internal class HandshakeReader
    {
        private RecordLayer recordLayer;
        private ByteBuffer byteBuffer;
        private byte[] buffer { get { return byteBuffer.Buffer; } }

        public HandshakeReader(RecordLayer recordLayer)
        {
            this.recordLayer = recordLayer;
            this.byteBuffer = new ByteBuffer();
        }

        public ClientHello ReadClientHello()
        {
            int cursor = 4;
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
            byte[] cipherSuites = null;
            byte[] legComprMeth = null;
            byte[] extensions = null;

            int minMsgLen = 2 + 32 + 1 + 2 + 1 + 2;

            LoadHandshake(HandshakeType.ClientHello, true);

            //AppendMinimum(minMsgLen, true);

            ClientHello msg = new ClientHello();

            ushort protocolVerson = MemMap.ToUShort2BytesBE(buffer, versionOffs);
            MemCpy.Copy(buffer, randomOffs, random, 0, 32);
            legacySessIdLen = (int)buffer[legSessIdOffs];
            legacySessId = new byte[legacySessIdLen];
            MemCpy.Copy(buffer, legSessIdOffs + 1, legacySessId, 0, legacySessIdLen);
            
            ciphSuitOffs = legacySessIdLen + 1;
            //LoadToLength(ciphSuitOffs + 1 + 2);
            ciphSuiteLen = MemMap.ToUShort2BytesBE(buffer, ciphSuitOffs);
            cipherSuites = new byte[ciphSuiteLen];
            MemCpy.Copy(buffer, ciphSuitOffs + 2, cipherSuites, 0, ciphSuiteLen);
            
            legCompMethOffs = ciphSuitOffs + 2 + ciphSuiteLen;
            //LoadToLength((legCompMethOffs + 1) + 1);
            legComprLen = buffer[legCompMethOffs];
            legComprMeth = new byte[legComprLen];
            MemCpy.Copy(buffer, legCompMethOffs + 1, legComprMeth, 0, legComprLen);

            extOffs = legCompMethOffs + 1 + legComprLen;
            //LoadToLength((legCompMethOffs + legComprLen + 1) + 2);
            extLen = MemMap.ToUShort2BytesBE(buffer, extOffs);
            extensions = new byte[extLen];

            //LoadToLength(extOffs + 1 + 2 + extLen);
            MemCpy.Copy(buffer, extOffs, extensions, 0, extLen);

            msg.ProtocolVersion = protocolVerson;
            msg.Random = random;
            msg.LegacySessionId = legacySessId;
            msg.CipherSuites = cipherSuites;
            msg.LegacyCompressionMethods = legComprMeth;
            msg.Extensions = extensions;

            return msg;
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


        private void LoadHandshake(HandshakeType expectedType ,bool isInitialClientHello = false)
        {
            while (byteBuffer.DataLength < 4)
            {
                LoadRecord(isInitialClientHello);
            }

            HandshakeType handshakeType = (HandshakeType)buffer[0];
            int msgLength = (buffer[1] << 16) | (buffer[2] << 08) | (buffer[3] << 00);

            Validate.Handshake.ValidHandshakeType(handshakeType);
            Validate.Handshake.ExpectedOrderOfHandshakeType(expectedType, handshakeType);

            while (byteBuffer.DataLength < 4 + msgLength)
            {
                recordLayer.Read();
            }
        }

        private void LoadRecord(bool isInitialClientHello = false)
        {
            RecordLayer.RecordInfo recordInfo = recordLayer.Read(isInitialClientHello);
            Validate.Handshake.NotZeroLengthFragmentsOfHandshake(recordInfo.Length);
            Validate.Handshake.RecordTypeIsHandshareAndNotInterleavedWithOtherRecordTypes(recordInfo.ContentType);

            byteBuffer.Append(recordLayer.RecordFragmentBytes, 0, recordInfo.Length);
        }   
    }
}
