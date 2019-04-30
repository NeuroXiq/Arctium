using Arctium.Connection.Tls.Protocol.BinaryOps.Builder;
using Arctium.Connection.Tls.Protocol.FormatConsts;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Arctium.Connection.Tls.Crypto
{
    class KeyExchangeRsaCrypto
    {
        public KeyExchangeRsaCrypto() { }

        public ClientKeyExchangeDecryptedRsa Decrypt(ClientKeyExchange clientKeyExchangeEncryptedRsa, X509Certificate2 cert)
        {
            byte[] encryptedBytes = clientKeyExchangeEncryptedRsa.ExchangeKeys;
            byte[] decryptedBytes = null;


            RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)cert.PrivateKey;
            decryptedBytes = rsa.Decrypt(encryptedBytes, RSAEncryptionPadding.Pkcs1);

            ClientKeyExchangeDecryptedRsaBuilder decryptedBuilder = new ClientKeyExchangeDecryptedRsaBuilder();
            ClientKeyExchangeDecryptedRsa keyExDecrypted = decryptedBuilder.Build(decryptedBytes);

            return keyExDecrypted;
        }
    }
}
