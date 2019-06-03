using System;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using Arctium.Connection.Tls.Protocol;
using Arctium.Connection.Tls.CryptoConfiguration;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Arctium.Connection.Tls.Operator.Tls12Operator.KeyExchangeServices
{
    class ClientKeyExchangeService
    {
        Context context;

        KeyExchangeAlgorithm currentKeyExchangeAlgo { get { return CryptoSuites.Get(context.allHandshakeMessages.ServerHello.CipherSuite).KeyExchangeAlgorithm; } }

        bool isRsa;
        byte[] rsaPremaster;

        public ClientKeyExchangeService(Context context)
        {
            this.context = context;
        }

        internal byte[] GetPremaster()
        {
            if (isRsa) return rsaPremaster;
            else
            {
                throw new NotImplementedException();
            }
        }

        internal bool ServerMustSendServerKeyExchange()
        {
            if (currentKeyExchangeAlgo == KeyExchangeAlgorithm.RSA) return false;
            else if (currentKeyExchangeAlgo == KeyExchangeAlgorithm.ECDHE) return true;
            else throw new Exception("INTERNAL::ClientKeyExchangeService");
        }

        public ClientKeyExchange CreateNewClientKeyExchangeMessage()
        {

            if (currentKeyExchangeAlgo != KeyExchangeAlgorithm.RSA)
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

            RSA rsaEncryption = context.allHandshakeMessages.ServerCertificate.ANS1Certificates[0].GetRSAPublicKey();

            byte[] encryptedPremaster = rsaEncryption.Encrypt(premaster, RSAEncryptionPadding.Pkcs1);

            ClientKeyExchange keyExchange = new ClientKeyExchange(encryptedPremaster);


            isRsa = true;
            this.rsaPremaster = premaster;

            return keyExchange;
        }
    }
}
