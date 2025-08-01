﻿using System.Collections.Generic;
using System;
using Arctium.Protocol.Tls.Protocol.RecordProtocol;
using Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Extensions.Enum;
using Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Enum;
using Arctium.Protocol.Tls.Tls12.CryptoConfiguration.Enum;

namespace Arctium.Protocol.Tls.Tls12.CryptoConfiguration
{
    //
    // hardcoded object oriented definitons of CipherSuite enum
    //

    static class CryptoSuites
    {
        private static Dictionary<CipherSuite, CryptoSuite> cryptoSuitesDefinitions = new Dictionary<CipherSuite, CryptoSuite>();


        public static CryptoSuite Get(CipherSuite cipherSuiteValue)
        {
            if (!cryptoSuitesDefinitions.ContainsKey(cipherSuiteValue))
            {
                throw new NotSupportedException("cipherSuiteValue is not currently defined");
            }


            return cryptoSuitesDefinitions[cipherSuiteValue];
        }

        static CryptoSuites()
        {
            AddStaticDefinitions();
        }

        private static void AddStaticDefinitions()
        {
            Add_TLS_NULL_WITH_NULL_NULL();

            Add_TLS_RSA_WITH_AES_128_CBC_SHA();

            Add_TLS_RSA_WITH_3DES_EDE_CBC_SHA();

            Add_TLS_RSA_WITH_AES_128_CBC_SHA();

            Add_TLS_RSA_WITH_AES_256_CBC_SHA();

            Add_TLS_RSA_WITH_AES_128_CBC_SHA256();

            Add_TLS_DHE_RSA_WITH_AES_128_CBC_SHA();

            Add_TLS_DHE_RSA_WITH_AES_256_CBC_SHA();

            /* ECC */

            Add_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA();

        }



        #region ECC methods

        private static void Add_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA()
        {
            CipherSuite baseSuite = CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA;

            RecordCryptoType recordCryptoType = new RecordCryptoType
                (CipherType.Block,
                BlockCipherMode.CBC,
                BulkCipherAlgorithm.AES,
                128,
                HashAlgorithmType.SHA1);

            CryptoSuite cryptoSuite = new CryptoSuite(
                baseSuite,
                KeyExchangeAlgorithm.ECDHE,
                SignatureAlgorithm.RSA,
                recordCryptoType);

            cryptoSuitesDefinitions[baseSuite] = cryptoSuite;
        }


        #endregion


        private static void Add_TLS_RSA_WITH_AES_128_CBC_SHA256()
        {
            CipherSuite baseSuite = CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256;

            RecordCryptoType rct = new RecordCryptoType(
                CipherType.Block,
                BlockCipherMode.CBC,
                BulkCipherAlgorithm.AES,
                128,
                HashAlgorithmType.SHA256);

            CryptoSuite s = new CryptoSuite(baseSuite, KeyExchangeAlgorithm.RSA, SignatureAlgorithm.NULL, rct);

            cryptoSuitesDefinitions[baseSuite] = s;
        }

        private static void Add_TLS_DHE_RSA_WITH_AES_256_CBC_SHA()
        {
            CipherSuite baseSuite = CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA;

            RecordCryptoType recordCrypto = new RecordCryptoType(
                CipherType.Block,
                BlockCipherMode.CBC,
                BulkCipherAlgorithm.AES,
                256,
                HashAlgorithmType.SHA1);

            CryptoSuite suite = new CryptoSuite(baseSuite, KeyExchangeAlgorithm.DHE, SignatureAlgorithm.RSA, recordCrypto);

            cryptoSuitesDefinitions[baseSuite] = suite;

        }

        private static void Add_TLS_DHE_RSA_WITH_AES_128_CBC_SHA()
        {
            CipherSuite baseSuite = CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA;

            RecordCryptoType recordCrypto = new RecordCryptoType(
                CipherType.Block,
                BlockCipherMode.CBC,
                BulkCipherAlgorithm.AES,
                128,
                HashAlgorithmType.SHA1);

            CryptoSuite suite = new CryptoSuite(baseSuite, KeyExchangeAlgorithm.DHE, SignatureAlgorithm.RSA, recordCrypto);

            cryptoSuitesDefinitions[baseSuite] = suite;
        }

        private static void Add_TLS_RSA_WITH_AES_256_CBC_SHA()
        {
            CipherSuite baseSuite = CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA;

            RecordCryptoType recordCrypto = new RecordCryptoType(
                CipherType.Block,
                BlockCipherMode.CBC,
                BulkCipherAlgorithm.AES,
                256,
                HashAlgorithmType.SHA1);

            CryptoSuite suite = new CryptoSuite(baseSuite, KeyExchangeAlgorithm.RSA, SignatureAlgorithm.NULL, recordCrypto);

            cryptoSuitesDefinitions[baseSuite] = suite;
        }

        private static void Add_TLS_RSA_WITH_3DES_EDE_CBC_SHA()
        {
            CipherSuite baseSuite = CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA;

            RecordCryptoType recordCryptoType = new RecordCryptoType(
                CipherType.Block,
                BlockCipherMode.CBC,
                BulkCipherAlgorithm.TDES,
                24 * 8,
                HashAlgorithmType.SHA1);

            CryptoSuite suite = new CryptoSuite(baseSuite, KeyExchangeAlgorithm.RSA, SignatureAlgorithm.NULL, recordCryptoType);

            cryptoSuitesDefinitions[baseSuite] = suite;
        }

        private static void Add_TLS_NULL_WITH_NULL_NULL()
        {
            CipherSuite baseSuite = CipherSuite.TLS_NULL_WITH_NULL_NULL;

            RecordCryptoType recordCryptoType = new RecordCryptoType(
                CipherType.Stream,
                BlockCipherMode.NULL,
                BulkCipherAlgorithm.NULL,
                0,
                HashAlgorithmType.NULL);

            CryptoSuite suite = new CryptoSuite(baseSuite, KeyExchangeAlgorithm.RSA, SignatureAlgorithm.NULL, recordCryptoType);

            cryptoSuitesDefinitions[baseSuite] = suite;
        }

        private static void Add_TLS_RSA_WITH_AES_128_CBC_SHA()
        {
            CipherSuite baseSuite = CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA;

            RecordCryptoType recordCryptoType = new RecordCryptoType(
                CipherType.Block,
                BlockCipherMode.CBC,
                BulkCipherAlgorithm.AES,
                128,
                HashAlgorithmType.SHA1);



            CryptoSuite suiteDefinition = new CryptoSuite(baseSuite, KeyExchangeAlgorithm.RSA, SignatureAlgorithm.NULL, recordCryptoType);

            cryptoSuitesDefinitions[baseSuite] = suiteDefinition;
        }
    }
}
