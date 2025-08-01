using Arctium.Protocol.Tls.Protocol;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Arctium.Protocol.Tls.Tls12.CryptoConfiguration;
using Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Extensions.Enum;

namespace Arctium.Protocol.Tls.ProtocolStream.RecordsLayer.RecordsLayer11
{
    static class RecordLayer11CryptoFactory
    {
        public static HMAC GetReadHMAC(SecParams11 secParams11)
        {
            return CreateHMAC(secParams11.RecordCryptoType.MACAlgorithm, secParams11.MacReadKey);
        }

        public static HMAC GetWriteHMAC(SecParams11 secParams11)
        {
            return CreateHMAC(secParams11.RecordCryptoType.MACAlgorithm, secParams11.MacWriteKey);
        }

        private static HMAC CreateHMAC(HashAlgorithmType mACAlgorithm, byte[] key)
        {
            switch (mACAlgorithm)
            {
                case HashAlgorithmType.NULL: return new NullHMAC();
                case HashAlgorithmType.MD5: return new HMACMD5(key);
                case HashAlgorithmType.SHA1: return new HMACSHA1(key);
                default: throw new Exception("Internal excepion RecordLayer11CryptoFactory undefined mac algorithm, improve validation!");
            }
        }

        public static SymmetricAlgorithm GetWriteCipher(SecParams11 secParams)
        {
            return GetCipher(secParams, secParams.BulkWriteKey);
        }

        public static SymmetricAlgorithm GetReadCipher(SecParams11 secParams)
        {
            return GetCipher(secParams, secParams.BulkReadKey);
        }

        private static SymmetricAlgorithm GetCipher(SecParams11 secParams, byte[] key)
        {
            if (secParams.RecordCryptoType.CipherType == CipherType.Block)
            {
                switch (secParams.RecordCryptoType.BulkCipherAlgorithm)
                {
                    case BulkCipherAlgorithm.AES:
                        return CreateAes(key, secParams.RecordCryptoType.BlockCipherMode);
                    default: throw new Exception("Internal error, not supported or invalid cipher type");
                }
            }
            else if (secParams.RecordCryptoType.CipherType == CipherType.Stream)
            {
                switch (secParams.RecordCryptoType.BulkCipherAlgorithm)
                {
                    case BulkCipherAlgorithm.NULL:
                        return new NullStreamCipher();
                    default: throw new Exception("Supported only for NULL or invalid param ? (internal error)");
                }
            }
            else throw new Exception("Internal error, invalid cipher type (not block or stream ? RecordLayer11CryptoFactory)");
        }

        private static SymmetricAlgorithm CreateAes(byte[] bulkReadKey, BlockCipherMode blockCipherMode)
        {
            SymmetricAlgorithm aes = new AesCryptoServiceProvider();
            aes.KeySize = bulkReadKey.Length * 8;
            aes.Key = bulkReadKey;
            aes.Mode = ConvertCipherMode(blockCipherMode);
            aes.Padding = PaddingMode.None;

            return aes;
        }

        private static CipherMode ConvertCipherMode(BlockCipherMode blockCipherMode)
        {
            switch (blockCipherMode)
            {
                case BlockCipherMode.ECB: return CipherMode.ECB;
                case BlockCipherMode.CBC: return CipherMode.CBC;
                case BlockCipherMode.OFB: return CipherMode.OFB;
                case BlockCipherMode.PCBC:
                case BlockCipherMode.CTR:
                case BlockCipherMode.CFB:
                default: throw new InvalidCastException("Invalid blockciphermode parameter, cannot convert (internal error, should not throw at RecordLayer11CryptoFactory)");
            }
        }

       
    }
}
