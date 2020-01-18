using Arctium.Connection.Tls.Tls12.Buffers;
using Arctium.Connection.Tls.Tls12.CryptoConfiguration;
using Arctium.Connection.Tls.Protocol;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using Arctium.Connection.Tls.Protocol.RecordProtocol;
using System;

namespace Arctium.Connection.Tls.Tls12.CryptoFunctions
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

        public static byte[] GenerateTls12MasterSecret(byte[] premaster, byte[] clientRandom, byte[] serverRandom)
        {
            return PRF.Prf12(premaster, "master secret", BufferTools.Join(clientRandom, serverRandom), 48);
        }

        public static Tls12Secrets GenerateTls12Secrets(RecordCryptoType cryptoType, byte[] masterSecret, byte[] clientRandom, byte[] serverRandom)
        {
            int macKeySize = CryptoConst.HashSize(cryptoType.MACAlgorithm) / 8;
            int keySize = cryptoType.KeySize / 8;
            //int ivSize = cryptoType.KeySize / 8;
            int keyBlockSize = 2 * (macKeySize + keySize);

            byte[] keyBlock = PRF.Prf12(masterSecret, "key expansion", BufferTools.Join(serverRandom, clientRandom), keyBlockSize);


            Tls12Secrets secrets = new Tls12Secrets();

            secrets.MasterSecret = masterSecret;
            //secrets.ClientIV = new byte[ivSize];
            //secrets.ServerIV = new byte[ivSize];
            secrets.ClientWriteKey = new byte[keySize];
            secrets.ServerWriteKey = new byte[keySize];
            secrets.ClientWriteMacKey = new byte[macKeySize];
            secrets.ServerWriteMacKey = new byte[macKeySize];

            Buffer.BlockCopy(keyBlock, 0, secrets.ClientWriteMacKey, 0, macKeySize);
            Buffer.BlockCopy(keyBlock, macKeySize, secrets.ServerWriteMacKey, 0, macKeySize);
            Buffer.BlockCopy(keyBlock, 2 * macKeySize, secrets.ClientWriteKey, 0, keySize);
            Buffer.BlockCopy(keyBlock, (2 * macKeySize) + keySize, secrets.ServerWriteKey, 0, keySize);
            //Buffer.BlockCopy(keyBlock, 2 * (macKeySize + keySize), secrets.ClientIV, 0, ivSize);
            //Buffer.BlockCopy(keyBlock, (2  * (macKeySize + keySize)) + ivSize, secrets.ServerIV, 0, ivSize);

            return secrets;
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
            PRF prf = new PRF();

            int hashSize = CryptoConst.HashSize(seed.RecordCryptoType.MACAlgorithm) / 8;
            int keySize = seed.RecordCryptoType.KeySize / 8;
            int keyBlockSize = (2 * hashSize) + (2 * keySize);

            //byte[] masterSeed = BufferTools.Join(seed.ClientRandom, seed.ServerRandom);
            //byte[] keyBlockSeed = BufferTools.Join(seed.ServerRandom, seed.ClientRandom);
            //
            //byte[] masterSecret = prf.Prf(seed.Premaster, "master secret", masterSeed, CryptoConst.Tls11MasterSecretLength);
            //byte[] keyBlock = prf.Prf(masterSecret, "key expansion", keyBlockSeed, keyBlockSize);

            byte[] masterSecret = prf.Prf11(seed.Premaster, "master secret", Join(seed.ClientRandom, seed.ServerRandom), CryptoConst.Tls11MasterSecretLength);

            byte[] keyBlock = prf.Prf11(masterSecret, "key expansion", Join(seed.ServerRandom, seed.ClientRandom), keyBlockSize);



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


//     """
//        Generate 100 bytes of pseudo-randomness using TLS1.2PRF-SHA256
//        """
//        secret = (
//            b'\x9b\xbe\x43\x6b\xa9\x40\xf0\x17\xb1\x76\x52\x84\x9a\x71\xdb\x35'
//        )
//        seed = (
//            b'\xa0\xba\x9f\x93\x6c\xda\x31\x18\x27\xa6\xf7\x96\xff\xd5\x19\x8c'
//        )
//        label = b'test label'
//        expected_output = (
//            b'\xe3\xf2\x29\xba\x72\x7b\xe1\x7b'
//            b'\x8d\x12\x26\x20\x55\x7c\xd4\x53'
//            b'\xc2\xaa\xb2\x1d\x07\xc3\xd4\x95'
//            b'\x32\x9b\x52\xd4\xe6\x1e\xdb\x5a'
//            b'\x6b\x30\x17\x91\xe9\x0d\x35\xc9'
//            b'\xc9\xa4\x6b\x4e\x14\xba\xf9\xaf'
//            b'\x0f\xa0\x22\xf7\x07\x7d\xef\x17'
//            b'\xab\xfd\x37\x97\xc0\x56\x4b\xab'
//            b'\x4f\xbc\x91\x66\x6e\x9d\xef\x9b'
//            b'\x97\xfc\xe3\x4f\x79\x67\x89\xba'
//            b'\xa4\x80\x82\xd1\x22\xee\x42\xc5'
//            b'\xa7\x2e\x5a\x51\x10\xff\xf7\x01'
//            b'\x87\x34\x7b\x66'
//)