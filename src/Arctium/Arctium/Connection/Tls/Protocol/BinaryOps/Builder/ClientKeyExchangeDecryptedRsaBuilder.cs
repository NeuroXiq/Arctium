using Arctium.Connection.Tls.Protocol.FormatConsts;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using System;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Builder
{
    class ClientKeyExchangeDecryptedRsaBuilder
    {
        public ClientKeyExchangeDecryptedRsaBuilder()
        {

        }

        public ClientKeyExchangeDecryptedRsa Build(byte[] decryptedBytes)
        {
            if (decryptedBytes.Length != 48)
            {
                throw new Exception("Invalid length of decrypted RSA client key exchange pre master secret");
            }

            ProtocolVersion version = new ProtocolVersion(decryptedBytes[0], decryptedBytes[1]);
            byte[] randomBytes = new byte[46];

            Array.Copy(decryptedBytes, 2, randomBytes, 0, 46);

            PremasterSecret premasterSecret = new PremasterSecret(version, randomBytes);
            ClientKeyExchangeDecryptedRsa ckxdr = new ClientKeyExchangeDecryptedRsa(premasterSecret);

            return ckxdr;
            
        }
    }
}
