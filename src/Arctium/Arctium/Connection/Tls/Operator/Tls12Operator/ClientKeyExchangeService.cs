using Arctium.Connection.Tls.CryptoConfiguration;
using Arctium.Connection.Tls.Protocol;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Arctium.Connection.Tls.Operator.Tls12Operator
{
    class ClientKeyExchangeService
    {
        Context currentOperatorContext;
        public byte[] Premaster;


        public ClientKeyExchangeService(Context context)
        {
            currentOperatorContext = context;
        }

        public ClientKeyExchange CreateNewClientKeyExchangeMessage()
        {
            CipherSuite selectedSuite = currentOperatorContext.allHandshakeMessages.ServerHello.CipherSuite;
            KeyExchangeAlgorithm keyExAlgo = CryptoSuites.Get(selectedSuite).KeyExchangeAlgorithm;

            if (keyExAlgo != KeyExchangeAlgorithm.RSA)
            {
                throw new NotSupportedException("ClientKeyExchangeService, Support only RSA key exchange, INTERNAL ERROR");
            }

            return GenerateRSAClientKeyExchange();
        }

        private ClientKeyExchange GenerateRSAClientKeyExchange()
        {
            byte[] premaster = new byte[48];
            (new Random()).NextBytes(premaster);
            premaster[0] = premaster[1] = 3;

            RSA rsaEncryption = currentOperatorContext.allHandshakeMessages.ServerCertificate.ANS1Certificates[0].GetRSAPublicKey();

            byte[] encryptedPremaster = rsaEncryption.Encrypt(premaster, RSAEncryptionPadding.Pkcs1);

            ClientKeyExchange keyExchange = new ClientKeyExchange(encryptedPremaster);

            this.Premaster = premaster;

            return keyExchange;
        }

        public bool ExpectToReadServerKeyExchange()
        {
            return false;
        }
    }
}
