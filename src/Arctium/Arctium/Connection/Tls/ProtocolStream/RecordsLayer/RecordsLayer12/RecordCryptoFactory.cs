using Arctium.Connection.Tls.CryptoConfiguration;
using Arctium.Connection.Tls.Protocol;
using System;
using System.Security.Cryptography;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12
{
    class RecordCryptoFactory
    {
        public static SecParams12 InitReadSecParams { get
            {
                return new SecParams12()
                {
                    RecordCryptoType = new RecordCryptoType(CipherType.Stream, BlockCipherMode.NULL, BulkCipherAlgorithm.NULL, 0, HashAlgorithmType.NULL),
                    BulkReadKey = new byte[0],
                    BulkWriteKey = new byte[0],
                    MacReadSecret = new byte[0],
                    MacWriteSecret = new byte[0],
                    MasterSecret = null
                };
            } }

        public static SecParams12 InitWriteSecParams { get { return InitReadSecParams; } }
                 
        public static RecordCrypto CreateRecordCrypto(SecParams12 secParams)
        {
            switch (secParams.RecordCryptoType.CipherType)
            {
                case CipherType.Stream: return BuildStreamRecordCrypto(secParams);
                case CipherType.Block: return BuildBlockRecordCrypto(secParams);
                case CipherType.Aead: return BuildAeadRecordCrypto(secParams);
                default: throw new Exception("Internal error, cipherType unrecognized int Tls11CryptoFactory");
            }
        }

        private static RecordCrypto BuildAeadRecordCrypto(SecParams12 secParams)
        {
            throw new NotImplementedException("aead not supported");
        }

        private static RecordCrypto BuildBlockRecordCrypto(SecParams12 secParams)
        {
            HMAC encryptHmac, decryptHmac;
            SymmetricAlgorithm encryptCipher, DecryptCipher;

            BuildHmacs(secParams, out encryptHmac, out decryptHmac);

            switch (secParams.RecordCryptoType.BulkCipherAlgorithm)
            {
                case BulkCipherAlgorithm.NULL:
                default: throw new NotSupportedException("Intenral error Tls12 algorithm not supported");
            }

        }

        private static RecordCrypto BuildStreamRecordCrypto(SecParams12 secParams)
        {
            HMAC encryptHmac, decryptHmac;
            SymmetricAlgorithm encryptCipher, decryptCipher;
            BuildHmacs(secParams, out encryptHmac, out decryptHmac);

            switch (secParams.RecordCryptoType.BulkCipherAlgorithm)
            {
                case BulkCipherAlgorithm.NULL:
                    encryptCipher = decryptCipher = new NullStreamCipherAlgorithm();
                    break;
                default: throw new NotSupportedException("not stream algo or not supported");
            }

            return new StreamRecordCrypto(encryptHmac, decryptHmac, encryptCipher, decryptCipher);
        }

        private static void BuildHmacs(SecParams12 secParams, out HMAC encryptHmac, out HMAC decryptHmac)
        {
            switch (secParams.RecordCryptoType.MACAlgorithm)
            {
                case HashAlgorithmType.NULL: encryptHmac = decryptHmac = new NullHMAC(); break;
                case HashAlgorithmType.MD5:
                    encryptHmac = new HMACMD5();
                    decryptHmac = new HMACMD5();
                    break;
                case HashAlgorithmType.SHA1:
                    encryptHmac = new HMACSHA1();
                    decryptHmac = new HMACSHA1();
                    break;
                case HashAlgorithmType.SHA256:
                    encryptHmac = new HMACSHA256();
                    decryptHmac = new HMACSHA256();
                    break;
                case HashAlgorithmType.SHA384:
                    encryptHmac = new HMACSHA384();
                    decryptHmac = new HMACSHA384();
                    break;
                case HashAlgorithmType.SHA512:
                    encryptHmac = new HMACSHA512();
                    decryptHmac = new HMACSHA512();
                    break;
                default: throw new NotSupportedException("Mac algorithm in TLS12 factory is not supporter or invalid");
            }

            encryptHmac.Key = secParams.MacWriteSecret;
            decryptHmac.Key = secParams.MacReadSecret;
        }
    }
}
