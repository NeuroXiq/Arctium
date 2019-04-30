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
            if (decryptedBytes.Length != HandshakeConst.ClientKeyExDecryptedRsaLength)
            {
                throw new Exception("Invalid length of decrypted RSA client key exchange pre master secret");
            }

            ProtocolVersion version = new ProtocolVersion(decryptedBytes[0], decryptedBytes[1]);
            byte[] randomBytes = new byte[HandshakeConst.ClientKeyExDecrytedRsaRandomLength];

            Array.Copy(decryptedBytes, 2, randomBytes, 0, HandshakeConst.ClientKeyExDecrytedRsaRandomLength);

            PremasterSecret premasterSecret = new PremasterSecret(version, randomBytes);
            ClientKeyExchangeDecryptedRsa ckxdr = new ClientKeyExchangeDecryptedRsa(premasterSecret);

            return ckxdr;
            
        }
    }
}
