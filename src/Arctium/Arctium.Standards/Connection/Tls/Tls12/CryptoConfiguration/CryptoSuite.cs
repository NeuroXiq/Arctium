﻿using Arctium.Standards.Connection.Tls.Tls12.CryptoConfiguration;
using Arctium.Standards.Connection.Tls.Protocol.HandshakeProtocol;
using Arctium.Standards.Connection.Tls.Protocol.HandshakeProtocol.Extensions.Enum;

namespace Arctium.Standards.Connection.Tls.Protocol
{
    ///<summary>Object oriented 'CipherSuite'</summary>
    class CryptoSuite
    {
        public CipherSuite CipherSuiteBase;

        public KeyExchangeAlgorithm KeyExchangeAlgorithm;
        public SignatureAlgorithm SigningAlgorithm;
        public RecordCryptoType RecordCryptoType;

        public CryptoSuite(
            CipherSuite baseSuite,
            KeyExchangeAlgorithm keyExchangeAlgorithm,
            SignatureAlgorithm signAlgorithm,
            RecordCryptoType recordCryptoType)
        {
            CipherSuiteBase = baseSuite;
            KeyExchangeAlgorithm = keyExchangeAlgorithm;
            RecordCryptoType = recordCryptoType;
            SigningAlgorithm = signAlgorithm;
        }

    }
}
