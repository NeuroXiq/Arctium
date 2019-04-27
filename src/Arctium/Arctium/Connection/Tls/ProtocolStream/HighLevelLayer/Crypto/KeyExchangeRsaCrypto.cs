using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Arctium.Connection.Tls.ProtocolStream.HighLevelLayer.Crypto
{
    class KeyExchangeRsaCrypto
    {
        public KeyExchangeRsaCrypto() { }

        public ClientKeyExchangeDecryptedRsa DecryptClientKeyExchange(ClientKeyExchange clientKeyExchangeEncryptedRsa, X509Certificate2 cert)
        {
            ClientKeyExchangeDecryptedRsa decryptedMsg = new ClientKeyExchangeDecryptedRsa();

            byte[] encryptedBytes = clientKeyExchangeEncryptedRsa.ExchangeKeys;
            byte[] decryptedBytes = null;



            RSAParameters rsaParams = new RSAParameters();

            RSA rsa = cert.GetRSAPrivateKey();
            decryptedBytes = rsa.Decrypt(encryptedBytes, RSAEncryptionPadding.Pkcs1);
            
            


            


            string a = "";


            throw new NotImplementerException();

        }

    }
}
