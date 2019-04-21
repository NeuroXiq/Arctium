namespace Arctium.Connection.Tls.Protocol
{
    public class SecurityParameters
    {
        public ConnectionEnd Entity;
        public BulkCipherAlgorithm BulkCipherAlgorithm;
        public CipherType CipherType;
        public MACAlgorithm MACAlgorithm;
        
        public byte KeySize;
        public byte KeyMaterialSize;
        public byte HashSize;
        public CompressionMethod CompressionAlgorithm;
        public byte[] MasterSecret; // = new byte[48];
        public byte[] ClientRandom; // = new byte[32];
        public byte[] ServerRandom; // = new byte[32];
    }
}
