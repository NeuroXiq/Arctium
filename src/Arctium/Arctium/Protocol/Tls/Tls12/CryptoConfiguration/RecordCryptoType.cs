using Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Extensions.Enum;
using Arctium.Protocol.Tls.Tls12.CryptoConfiguration.Enum;

namespace Arctium.Protocol.Tls.Tls12.CryptoConfiguration
{
    class RecordCryptoType
    {
        public CipherType CipherType;

        public BulkCipherAlgorithm BulkCipherAlgorithm;
        public HashAlgorithmType MACAlgorithm;

        ///<summary>Key size in bits</summary>
        public int KeySize;


        ///<summary>Only for Block ciphers</summary>
        public BlockCipherMode BlockCipherMode;

        public RecordCryptoType(CipherType cipherType,
            BlockCipherMode blockCipherMode,
            BulkCipherAlgorithm bulkCipherAlgorithm,
            int keySize,
            HashAlgorithmType macAlgorithm)
        {
            CipherType = cipherType;
            BlockCipherMode = blockCipherMode;
            BulkCipherAlgorithm = bulkCipherAlgorithm;
            MACAlgorithm = macAlgorithm;
            KeySize = keySize;
        }
    }
}
