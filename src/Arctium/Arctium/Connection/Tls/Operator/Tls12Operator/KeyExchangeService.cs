using Arctium.Connection.Tls.CryptoConfiguration;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Arctium.Connection.Tls.Operator.Tls12Operator
{
    class KeyExchangeService
    {
        KeyExchangeAlgorithm keyExchangeAlgorithm;
        SignatureAlgorithm signatureAlgorithm;
        OnHandshakeState handler;
        X509Certificate2 certificate;

        public KeyExchangeService(KeyExchangeAlgorithm keyExchangeAlgorithm, SignatureAlgorithm signAlgorithm, X509Certificate2 cert, OnHandshakeState handler)
        {
            this.certificate = cert;
            this.keyExchangeAlgorithm = keyExchangeAlgorithm;
            this.signatureAlgorithm = signAlgorithm;
            this.handler = handler;

            if (keyExchangeAlgorithm != KeyExchangeAlgorithm.RSA)
            {
                throw new NotImplementedException("only RsA implemented");
            }
        }


        public void SendServerKeyExchange(HandshakeMessages12 messagesContext)
        {
            
        }

        ///<summary>returns premaster secret</summary>
        public void ReceiveClientKeyExchange(HandshakeMessages12 context)
        {
            Handshake msg = handler.Read();

            if (msg.MsgType != HandshakeType.ClientKeyExchange) throw new Exception("expected client key exchange");

            ClientKeyExchange cke = (ClientKeyExchange)msg;


            context.ClientKeyExchange = cke;
        }

        public byte[] GetPremasterAsServer(HandshakeMessages12 context)
        {
            switch (keyExchangeAlgorithm)
            {
                case KeyExchangeAlgorithm.RSA:
                    return DecryptRSA(context.ClientKeyExchange.ExchangeKeys);
                case KeyExchangeAlgorithm.ECDHE:
                default: throw new Exception("Internal error. this exception should never throw (invalid parameters valdation)");
            }
        }

        private byte[] DecryptRSA(byte[] exchangeKeys)
        {
            RSA rsa = certificate.GetRSAPrivateKey();

            return rsa.Decrypt(exchangeKeys, RSAEncryptionPadding.Pkcs1);
        }
    }
}
