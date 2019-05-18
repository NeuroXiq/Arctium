using Arctium.Connection.Tls.CryptoConfiguration;
using System;

namespace Arctium.Connection.Tls.Operator.Tls12Operator
{
    class KeyExchangeService
    {
        KeyExchangeAlgorithm keyExchangeAlgorithm;
        SignatureAlgorithm signatureAlgorithm;
        OnHandshakeState handler;

        public KeyExchangeService(KeyExchangeAlgorithm keyExchangeAlgorithm, SignatureAlgorithm signAlgorithm, OnHandshakeState handler)
        {
            this.keyExchangeAlgorithm = keyExchangeAlgorithm;
            this.signatureAlgorithm = signAlgorithm;
            this.handler = handler;
        }


        public void SendServerKeyExchange(HandshakeMessages12 messagesContext)
        {
            if (keyExchangeAlgorithm != KeyExchangeAlgorithm.RSA)
            {
                throw new NotImplementedException("only RsA implemented");
            }
        }

        ///<summary>returns premaster secret</summary>
        public byte[] ReceiveClientKeyExchange(HandshakeMessages12 context)
        {
            return null;
        }
    }
}
