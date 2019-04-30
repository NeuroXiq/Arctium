using Arctium.Connection.Tls.Protocol.RecordProtocol;

namespace Arctium.Connection.Tls.Protocol
{
    struct RecordCryptoType
    {
        public CipherType CipherType;
        ///<summary>Only for Block ciphers</summary>
        public BlockCipherMode BlockCipherMode;
        public BulkCipherAlgorithm BulkCipherAlgorithm;
        public MACAlgorithm MACAlgorithm;
    }
}
