namespace Arctium.Standards.Connection.Tls.Protocol.HandshakeProtocol
{
    class ClientKeyExchangeDecryptedRsa
    {
        public PremasterSecret PreMasterSecret;

        public ClientKeyExchangeDecryptedRsa(PremasterSecret preMasterSecret)
        {
            PreMasterSecret = preMasterSecret;
        }
    }
}
