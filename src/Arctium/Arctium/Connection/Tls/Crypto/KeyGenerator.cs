using Arctium.Connection.Tls.Protocol;
using System;
using Arctium.Connection.Tls.Protocol.RecordProtocol;
using Arctium.Connection.Tls.Protocol.FormatConsts;

namespace Arctium.Connection.Tls.Crypto
{
    class KeyGenerator
    {
        public struct KeyGenerationSeed
        {
            public byte[] PremasterSecret;
            public byte[] ClientRandom;
            public byte[] ServerRandom;
            public RecordCryptoType RecordCryptoType;
        }

        public KeyGenerator() { }


        public TlsKeys GenerateKeys(KeyGenerationSeed keySeed)
        {
            PseudoRandomFunction prf = new PseudoRandomFunction();

            byte[] randomSeed = Join(keySeed.ClientRandom, keySeed.ServerRandom);

            int hashSize = GetHashSize(keySeed.RecordCryptoType.MACAlgorithm);
            int keySize = keySeed.RecordCryptoType.KeySize/8;
            int keyBlockSize = (2 * hashSize) + (2 * keySize);

            byte[] masterSecret = prf.Prf(keySeed.PremasterSecret, "master secret", randomSeed, CryptoConst.MasterSecretLength);

            byte[] keyBlock = prf.Prf(masterSecret, "key expansion", randomSeed, keyBlockSize);

            TlsKeys keys = PartitionToKeys(keyBlock, hashSize, keySize);


            return keys;

        }

        private TlsKeys PartitionToKeys(byte[] keyBlock, int hashSize, int keySize)
        {
            byte[] clientWriteMacSecret = new byte[hashSize];
            byte[] serverWriteMacSecret = new byte[hashSize];
            byte[] clientWriteKey = new byte[keySize];
            byte[] serverWriteKey = new byte[keySize];

            Buffer.BlockCopy(keyBlock, 0, clientWriteMacSecret, 0, hashSize);
            Buffer.BlockCopy(keyBlock, hashSize, serverWriteMacSecret, 0, hashSize);
            Buffer.BlockCopy(keyBlock, 2 * hashSize, clientWriteKey, 0, keySize);
            Buffer.BlockCopy(keyBlock, (2 * hashSize) + keySize, serverWriteKey, 0, keySize);

            TlsKeys keys = new TlsKeys();
            keys.ClientWriteKey = clientWriteKey;
            keys.ServerWriteKey = serverWriteKey;
            keys.ClientWriteMacSecret = clientWriteMacSecret;
            keys.ServerWriteMacSecret = serverWriteMacSecret;

            return keys;
        }

        private byte[] Join(byte[] clientRandom, byte[] serverRandom)
        {
            byte[] result = new byte[clientRandom.Length + serverRandom.Length];

            Buffer.BlockCopy(clientRandom, 0, result, 0, clientRandom.Length);
            Buffer.BlockCopy(serverRandom, 0, result, clientRandom.Length, serverRandom.Length);

            return result;
        }

        private int GetHashSize(MACAlgorithm macAlgorithm)
        {
            switch (macAlgorithm)
            {
                case MACAlgorithm.NULL:
                    return 0;
                case MACAlgorithm.MD5:
                    return 16;
                case MACAlgorithm.SHA:
                    return 20;
                default:
                    throw new NotImplementedException("internal error, get hash size not implemented in KeyGenerator");
            }
        }
    }
}
