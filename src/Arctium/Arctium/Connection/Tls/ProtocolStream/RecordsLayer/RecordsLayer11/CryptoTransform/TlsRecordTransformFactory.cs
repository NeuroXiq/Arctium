using Arctium.Connection.Tls.CryptoConfiguration;
using Arctium.Connection.Tls.Protocol;
using System;
using System.Security.Cryptography;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer11.CryptoTransform
{
    class TlsRecordTransformFactory
    {
        public TlsRecordTransformFactory() { }

        public TlsRecordTransform BuildTlsRecordTransform(SecParams11 securityParameters)
        {
            RecordCryptoType crypto = securityParameters.RecordCryptoType;

            Cipher cipherTransform;
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
                case CompressionMethod.NULL:
                    compressionTransform = new NullCompressionTransform();
                    break;
                default:
                    throw new NotImplementedException("Current value of 'SecParams.CompressionMethod' is invalid or not implemented");
            }

            HMAC readHmac, writeHmac;
            BuildHmacFunctions(securityParameters, out readHmac, out writeHmac);

            HmacService hmacService = new HmacService(securityParameters.RecordCryptoType.MACAlgorithm, readHmac, writeHmac, securityParameters.CompressionMethod);
            TlsRecordTransform recordTransform = new TlsRecordTransform(cipherTransform, compressionTransform, hmacService);

            return recordTransform;
        }

        private Cipher BuildBlockCipherTransform(SecParams11 securityParameters)
        {
            SymmetricAlgorithm writeCipher, readCipher;
            HMAC writeMac, readMac;


            switch (securityParameters.RecordCryptoType.BulkCipherAlgorithm)
            {
                case BulkCipherAlgorithm.AES:
                    BuildAesCipherTransform(securityParameters, out readCipher, out writeCipher);
                    break;
                default:
                    throw new NotSupportedException("Only support for AES (debug)");
            }

            BuildHmacFunctions(securityParameters, out readMac, out writeMac);

            BlockCipher blockCipherTransform = new BlockCipher(
                readCipher,
                writeCipher,
                HashAlgorithmLength(securityParameters.RecordCryptoType.MACAlgorithm));

            return blockCipherTransform;
        }

        private int HashAlgorithmLength(MACAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case MACAlgorithm.NULL:
                    return 0;
                    break;
                case MACAlgorithm.MD5:
                    return 16;
                    break;
                case MACAlgorithm.SHA:
                    return 20;
                    break;
                default:
                    throw new Exception("not supported algorithm");
                    break;
            }
        }

        private void BuildHmacFunctions(SecParams11 securityParameters, out HMAC readMac, out HMAC writeMac)
        {
            switch (securityParameters.RecordCryptoType.MACAlgorithm)
            {
                case MACAlgorithm.NULL:
                    readMac = null;
                    writeMac = null;
                    break;
                case MACAlgorithm.MD5:
                    readMac = new HMACMD5(securityParameters.MacReadSecret);
                    writeMac = new HMACMD5(securityParameters.MacWriteSecret);
                    break;
                case MACAlgorithm.SHA:
                    readMac = new HMACSHA1(securityParameters.MacReadSecret);
                    writeMac = new HMACSHA1(securityParameters.MacWriteSecret);
                    break;
                default:
                    throw new NotSupportedException("'MACAlgorithm' is not supported or contains invalid value");
            }
        }

        private void BuildAesCipherTransform(SecParams11 secParams, out SymmetricAlgorithm readAlgo, out SymmetricAlgorithm writeAlgo)
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

        private Cipher BuildStreamCipherTransform(SecParams11 securityParameters)
        {
            switch (securityParameters.RecordCryptoType.BulkCipherAlgorithm)
            {
                case BulkCipherAlgorithm.NULL:
                     return new NullStreamCipherTransform();
                 default:
                    throw new NotSupportedException("Stream ciphers support only NULL type");
            }
        }
    }
}
