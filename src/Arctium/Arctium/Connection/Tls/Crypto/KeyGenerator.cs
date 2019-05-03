using Arctium.Connection.Tls.Protocol;
using System;
using Arctium.Connection.Tls.Protocol.RecordProtocol;
using Arctium.Connection.Tls.Protocol.FormatConsts;
using System.Globalization;

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

            //byte[] randomSeed = Join(keySeed.ServerRandom, keySeed.ClientRandom);

            int hashSize = GetHashSize(keySeed.RecordCryptoType.MACAlgorithm);
            int keySize = keySeed.RecordCryptoType.KeySize/8;
            int keyBlockSize = (2 * hashSize) + (2 * keySize);


            //string expectedStr = "d3d4d1e349b5d515044666d51de32bab258cb521b6b053463e354832fd976754443bcf9a296519bc289abcbc1187e4ebd31e602353776c408aafb74cbc85eff69255f9788faa184cbb957a9819d84a5d7eb006eb459d3ae8de9810454b8b2d8f1afbc655a8c9a013";
            //byte[] expected = HEX(expectedStr);
            //
            //byte[] seed = new byte[64];
            //byte[] secred = new byte[48];
            //for (int i = 0; i < 64; i++) seed[i] = 0xcd;
            //for (int i = 0; i < 48; i++) secred[i] = 0xab;
            //
            //byte[] master = prf.Prf(secred, "PRF Testvector", seed, 104);
            //
            //
            //for (int i = 0; i < 104; i++)
            //{
            //    Console.WriteLine("{0,-3}| {1,-3:X2} {2,-3:X2} {3,-3:X2}", i,expected[i], expected[i] == master[i] ? "=" : "!", master[i]);
            //}
            //
            //return new TlsKeys();

            byte[] masterSecret = prf.Prf(keySeed.PremasterSecret, "master secret", Join(keySeed.ClientRandom,keySeed.ServerRandom), CryptoConst.MasterSecretLength);
            
            byte[] keyBlock = prf.Prf(masterSecret, "key expansion", Join(keySeed.ServerRandom,keySeed.ClientRandom), keyBlockSize);
            
            TlsKeys keys = PartitionToKeys(keyBlock, hashSize, keySize);
            
            
            return keys;
            
        }

        private byte[] HEX(string expectedStr)
        {
            byte[] res = new byte[expectedStr.Length / 2];
            for (int i = 0; i < expectedStr.Length/2; i++)
            {
                res[i] = Convert.ToByte(expectedStr.Substring(i * 2, 2), 16);
            }

            return res;
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
