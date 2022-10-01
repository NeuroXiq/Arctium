using Arctium.Standards.Connection.Tls.Tls12.CryptoConfiguration;
using Arctium.Standards.Connection.Tls.Protocol.HandshakeProtocol.Extensions.Enum;

namespace Arctium.Standards.Connection.Tls.Protocol
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
