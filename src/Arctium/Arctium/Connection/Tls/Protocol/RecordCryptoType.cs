using Arctium.Connection.Tls.Protocol.RecordProtocol;

namespace Arctium.Connection.Tls.Protocol
{
    class RecordCryptoType
    {
        public CipherType CipherType;
        ///<summary>Only for Block ciphers</summary>
        public BlockCipherMode BlockCipherMode;
        public BulkCipherAlgorithm BulkCipherAlgorithm;
        public MACAlgorithm MACAlgorithm;
        ///<summary>Key size in bits</summary>
        public int KeySize;

        public RecordCryptoType(CipherType cipherType,
            BlockCipherMode blockCipherMode,
            BulkCipherAlgorithm bulkCipherAlgorithm,
            int keySize,
            MACAlgorithm macAlgorithm)
        {
            CipherType = cipherType;
            BlockCipherMode = blockCipherMode;
            BulkCipherAlgorithm = bulkCipherAlgorithm;
            MACAlgorithm = macAlgorithm;
            KeySize = keySize;
        }
    }
}
