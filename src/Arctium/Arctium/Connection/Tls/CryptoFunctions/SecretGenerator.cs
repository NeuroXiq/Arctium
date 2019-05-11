using Arctium.Connection.Tls.Buffers;
using Arctium.Connection.Tls.CryptoConfiguration;
using Arctium.Connection.Tls.Protocol;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using Arctium.Connection.Tls.Protocol.RecordProtocol;
using System;

namespace Arctium.Connection.Tls.CryptoFunctions
{
    class SecretGenerator
    {
        public SecretGenerator() { }

        public struct SecParams11Seed
        {
            public byte[] Premaster;
            public byte[] ClientRandom;
            public byte[] ServerRandom;
            public RecordCryptoType RecordCryptoType;
            public CompressionMethod CompressionMethod;
            public ConnectionEnd HostType;
        }

        private byte[] Join(byte[] clientRandom, byte[] serverRandom)
        {
            byte[] result = new byte[clientRandom.Length + serverRandom.Length];

            Buffer.BlockCopy(clientRandom, 0, result, 0, clientRandom.Length);
            Buffer.BlockCopy(serverRandom, 0, result, clientRandom.Length, serverRandom.Length);

            return result;
        }

        public SecParams11 GenerateSecParams11(SecParams11Seed seed)
        {
            PseudoRandomFunction prf = new PseudoRandomFunction();

            int hashSize = CryptoConst.HashSize(seed.RecordCryptoType.MACAlgorithm) / 8;
            int keySize = seed.RecordCryptoType.KeySize / 8;
            int keyBlockSize = (2 * hashSize) + (2 * keySize);

            //byte[] masterSeed = BufferTools.Join(seed.ClientRandom, seed.ServerRandom);
            //byte[] keyBlockSeed = BufferTools.Join(seed.ServerRandom, seed.ClientRandom);
            //
            //byte[] masterSecret = prf.Prf(seed.Premaster, "master secret", masterSeed, CryptoConst.Tls11MasterSecretLength);
            //byte[] keyBlock = prf.Prf(masterSecret, "key expansion", keyBlockSeed, keyBlockSize);

            byte[] masterSecret = prf.Prf(seed.Premaster, "master secret", Join(seed.ClientRandom, seed.ServerRandom), CryptoConst.Tls11MasterSecretLength);

            byte[] keyBlock = prf.Prf(masterSecret, "key expansion", Join(seed.ServerRandom, seed.ClientRandom), keyBlockSize);



            Tls11KeyBlock keys = PartitionToTls11Keys(keyBlock, hashSize, keySize);

            SecParams11 secParams = new SecParams11();
            secParams.MasterSecret = masterSecret;
            secParams.RecordCryptoType = seed.RecordCryptoType;
            secParams.CompressionMethod = seed.CompressionMethod;

            if (seed.HostType == ConnectionEnd.Client)
            {
                secParams.BulkReadKey = keys.ServerWriteKey;
                secParams.BulkWriteKey = keys.ClientWriteKey;
                secParams.MacWriteKey = keys.ClientWriteMacSecret;
                secParams.MacReadKey = keys.ServerWriteMacSecret;
            }
            else
            {
                secParams.BulkReadKey = keys.ClientWriteKey;
                secParams.BulkWriteKey = keys.ServerWriteKey;
                secParams.MacWriteKey = keys.ServerWriteMacSecret;
                secParams.MacReadKey = keys.ClientWriteMacSecret;
            }

            return secParams;
        }

        private Tls11KeyBlock PartitionToTls11Keys(byte[] keyBlock, int hashSize, int keySize)
        {
            byte[] clientWriteMacSecret = new byte[hashSize];
            byte[] serverWriteMacSecret = new byte[hashSize];
            byte[] clientWriteKey = new byte[keySize];
            byte[] serverWriteKey = new byte[keySize];

            Buffer.BlockCopy(keyBlock, 0, clientWriteMacSecret, 0, hashSize);
            Buffer.BlockCopy(keyBlock, hashSize, serverWriteMacSecret, 0, hashSize);
            Buffer.BlockCopy(keyBlock, 2 * hashSize, clientWriteKey, 0, keySize);
            Buffer.BlockCopy(keyBlock, (2 * hashSize) + keySize, serverWriteKey, 0, keySize);

            Tls11KeyBlock keys = new Tls11KeyBlock();
            keys.ClientWriteKey = clientWriteKey;
            keys.ServerWriteKey = serverWriteKey;
            keys.ClientWriteMacSecret = clientWriteMacSecret;
            keys.ServerWriteMacSecret = serverWriteMacSecret;

            return keys;
        }
    }
}
//TLS1.1::::
//string expectedStr = "d3d4 d1e3 49b5 d515 0446 66d5 1de3 2bab 258cb521b6b053463e354832fd976754443bcf9a296519bc289abcbc1187e4ebd31e602353776c408aafb74cbc85eff69255f9788faa184cbb957a9819d84a5d7eb006eb459d3ae8de9810454b8b2d8f1afbc655a8c9a013";
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