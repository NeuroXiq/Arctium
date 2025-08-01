namespace Arctium.Protocol.Tls.Protocol.HandshakeProtocol
{
    class PremasterSecret
    {
        public ProtocolVersion ClientVersion;
        public byte[] Random;

        public byte[] RawBytes;

        public PremasterSecret(ProtocolVersion version, byte[] random)
        {
            ClientVersion = version;
            Random = random;
            RawBytes = new byte[2 + random.Length];
            RawBytes[0] = version.Major;
            RawBytes[1] = version.Minor;

            for (int i = 0; i < random.Length; i++)
                RawBytes[2 + i] = random[i];
            
        }
    }
}
