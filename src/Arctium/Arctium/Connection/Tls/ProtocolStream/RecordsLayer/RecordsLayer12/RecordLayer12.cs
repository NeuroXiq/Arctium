using Arctium.Connection.Tls.Buffers;
using Arctium.Connection.Tls.CryptoConfiguration;
using Arctium.Connection.Tls.Protocol.RecordProtocol;
using System.IO;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12
{
    class RecordLayer12
    {
        RecordsBuffer recordsBuffer;

        private byte[] WriteBuffer;

        FragmentCrypto writeCrypto;
        FragmentCrypto readCrypto;

        RecordLayer12(Stream innerStream)
        {
            recordsBuffer = new RecordsBuffer();
        }

        public RecordLayer12 Initialize(Stream innerStream)
        {
            return new RecordLayer12(innerStream);
        }

        public int LoadFragment(out ContentType contentType)
        {
            contentType = ContentType.Alert;

            //recordsBuffer.EnsureRecord();
            



            return 1;
        }

        public void ReadFragment(byte[] buffer, int offset)
        {

        }

        public void ChangeWriteCipherSpec(SecParams12 secParams)
        {

        }

        public void ChangeReadCipherSpec(SecParams12 secParams)
        {

        }
    }
}
