using Arctium.Connection.Tls.Protocol;
using System;
using System.Security.Cryptography;

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
                    compressionTransform = new NullCompressionTransform();
                    break;
                default:
                    throw new NotImplementedException("Current value of 'SecParams.CompressionMethod' is invalid or not implemented");
            }

            TlsRecordTransform recordTransform = new TlsRecordTransform(cipherTransform, compressionTransform);

            return recordTransform;
        }

        private CipherTransform BuildBlockCipherTransform(SecParams securityParameters)
        {
            SymmetricAlgorithm writeCipher, readCipher;
            HMAC writeMac, readMac;


            switch (securityParameters.RecordCryptoType.BulkCipherAlgorithm)
            {
                case Protocol.RecordProtocol.BulkCipherAlgorithm.AES:
                    BuildAesCipherTransform(securityParameters, out readCipher, out writeCipher);
                    break;
                default:
                    throw new NotSupportedException("Only support for AES (debug)");
            }

            BuildHmacFunctions(securityParameters, out readMac, out writeMac);

            BlockCipherTransform blockCipherTransform = new BlockCipherTransform(readCipher, writeCipher, readMac, writeMac);

            return blockCipherTransform;
        }

        private void BuildHmacFunctions(SecParams securityParameters, out HMAC readMac, out HMAC writeMac)
        {
            switch (securityParameters.RecordCryptoType.MACAlgorithm)
            {
                case Protocol.RecordProtocol.MACAlgorithm.NULL:
                    throw new NotImplementedException("HMAC null not implemented");
                case Protocol.RecordProtocol.MACAlgorithm.MD5:
                    readMac = new HMACMD5(securityParameters.MacReadSecret);
                    writeMac = new HMACMD5(securityParameters.MacWriteSecret);
                    break;
                case Protocol.RecordProtocol.MACAlgorithm.SHA:
                    readMac = new HMACSHA1(securityParameters.MacReadSecret);
                    writeMac = new HMACSHA1(securityParameters.MacWriteSecret);
                    break;
                default:
                    throw new NotSupportedException("'MACAlgorithm' is not supported or contains invalid value");
            }
        }

        private void BuildAesCipherTransform(SecParams secParams, out SymmetricAlgorithm readAlgo, out SymmetricAlgorithm writeAlgo)
        {
            int keySizeInBits = secParams.RecordCryptoType.KeySize;
            if (keySizeInBits != 128 && keySizeInBits != 192 && keySizeInBits != 256)
                throw new InvalidOperationException("Invalid AES encryption key size. Possible values are 128, 192, 256 but current is: " + keySizeInBits);

            AesCryptoServiceProvider aesWrite = new AesCryptoServiceProvider();
            aesWrite.Key = secParams.KeyWriteSecret;
            AesCryptoServiceProvider aesRead = new AesCryptoServiceProvider();
            aesRead.Key = secParams.KeyReadSecret;

            readAlgo = aesRead;
            writeAlgo = aesWrite;
        }

        private CipherTransform BuildStreamCipherTransform(SecParams securityParameters)
        {
            switch (securityParameters.RecordCryptoType.BulkCipherAlgorithm)
            {
                case Protocol.RecordProtocol.BulkCipherAlgorithm.NULL:
                     return new NullStreamCipherTransform();
                 default:
                    throw new NotSupportedException("Stream ciphers support only NULL type");
            }
        }
    }
}
