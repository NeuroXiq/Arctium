using Arctium.Connection.Tls.Protocol;
using System;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.CryptoTransform
{
    class TlsRecordTransformFactory
    {
        public TlsRecordTransformFactory() { }



        public TlsRecordTransform BuildTlsRecordTransform(SecParams securityParameters)
        {
            RecordCryptoType crypto = securityParameters.RecordCryptoType;

            CipherTransform cipherTransform;
            CompressionTransform compressionTransform;

            switch (crypto.CipherType)
            {
                case Protocol.RecordProtocol.CipherType.Stream:
                    cipherTransform = BuildStreamCipherTransform(securityParameters);
                    break;
                case Protocol.RecordProtocol.CipherType.Block:
                    cipherTransform = BuildBlockCipherTransform(securityParameters);
                    break;
                default:
                    throw new NotImplementedException("Current value of 'SecParams.CipherType' is invalid or not implemented");
            }

            switch (securityParameters.CompressionMethod)
            {
                case Protocol.RecordProtocol.CompressionMethod.NULL:
                    break;
                default:
                    throw new NotImplementedException("Current value of 'SecParams.CompressionMethod' is invalid or not implemented");
                    break;
            }

        }

        private CipherTransform BuildBlockCipherTransform(SecParams securityParameters)
        {
            throw new NotImplementedException();
        }

        private CipherTransform BuildStreamCipherTransform(SecParams securityParameters)
        {
            throw new NotImplementedException();
        }
    }
}
