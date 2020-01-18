using Arctium.Connection.Tls.Tls12.CryptoConfiguration;
using Arctium.Connection.Tls.Protocol;
using System;
using System.Security.Cryptography;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions.Enum;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12
{
    class RecordCryptoFactory
    {
        public static RecordLayer12Params InitReadSecParams { get
            {
                return new RecordLayer12Params()
                {
                    RecordCryptoType = new RecordCryptoType(CipherType.Stream, BlockCipherMode.NULL, BulkCipherAlgorithm.NULL, 0, HashAlgorithmType.NULL),
                    BulkKey = new byte[0],
                    MacKey = new byte[0]
                };
            } }

        public static RecordLayer12Params InitWriteSecParams { get { return InitReadSecParams; } }

        public static IRecordCryptoFilter CreateRecordCryptoFilter(RecordLayer12Params secParams)
        {
            switch (secParams.RecordCryptoType.CipherType)
            {
                case CipherType.Stream: return BuildStreamRecordCrypto(secParams);
                case CipherType.Block: return BuildBlockRecordCrypto(secParams);
                case CipherType.Aead: return BuildAeadRecordCrypto(secParams);
                default: throw new Exception("Internal error, cipherType unrecognized int Tls11CryptoFactory");
            }
        }

        private static IRecordCryptoFilter BuildAeadRecordCrypto(RecordLayer12Params secParams)
        {
            throw new NotImplementedException("aead not supported");
        }

        private static IRecordCryptoFilter BuildBlockRecordCrypto(RecordLayer12Params secParams)
        {
            HMAC hmac = BuildHmac(secParams);
            switch (secParams.RecordCryptoType.BulkCipherAlgorithm)
            {
                case BulkCipherAlgorithm.AES:
                    CipherMode mode = GetBlockCipherMode(secParams);
                    return new BlockFragmentCrypto(hmac, new AesCryptoServiceProvider() { Key = secParams.BulkKey, Padding = PaddingMode.None, Mode = mode });
                default: throw new NotSupportedException("Intenral error Tls12 algorithm not supported");
            }
        }

        private static CipherMode GetBlockCipherMode(RecordLayer12Params secParams)
        {
            switch (secParams.RecordCryptoType.BlockCipherMode)
            {
                case BlockCipherMode.ECB: return CipherMode.ECB;
                case BlockCipherMode.CBC:  return CipherMode.CBC;
                case BlockCipherMode.OFB: return CipherMode.OFB;
                default: throw new Exception("internal error, cipher mode not currently defined in cryptofactory");
            }
        }

        private static IRecordCryptoFilter BuildStreamRecordCrypto(RecordLayer12Params secParams)
        {
            HMAC hmac = BuildHmac(secParams);
            SymmetricAlgorithm cipher;

            switch (secParams.RecordCryptoType.BulkCipherAlgorithm)
            {
                case BulkCipherAlgorithm.NULL:
                    cipher = new NullStreamCipherAlgorithm();
                    break;
                default: throw new NotSupportedException("not stream algo or not supported");
            }

            return new StreamFragmentCrypto(hmac, cipher);
        }

        private static HMAC BuildHmac(RecordLayer12Params secParams)
        {
            HMAC resultHMac;

            switch (secParams.RecordCryptoType.MACAlgorithm)
            {
                case HashAlgorithmType.NULL:
                    resultHMac = new NullHMAC();
                    break;
                case HashAlgorithmType.MD5:
                    resultHMac = new HMACMD5(secParams.MacKey);
                    break;
                case HashAlgorithmType.SHA1:
                    resultHMac = new HMACSHA1(secParams.MacKey);
                    break;
                case HashAlgorithmType.SHA256:
                    resultHMac = new HMACSHA256(secParams.MacKey);
                    break;
                case HashAlgorithmType.SHA384:
                    resultHMac = new HMACSHA384(secParams.MacKey);
                    break;
                case HashAlgorithmType.SHA512:
                    resultHMac = new HMACSHA512(secParams.MacKey);
                    break;
                default: throw new NotSupportedException("Mac algorithm in TLS12 factory is not supporter or invalid");
            }

            return resultHMac;
        }
    }
}
