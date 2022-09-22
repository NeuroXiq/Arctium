using Arctium.Cryptography.HashFunctions.MAC;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Binary;
using Arctium.Tests.Core;
using Arctium.Tests.Core.Attributes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Tests.Cryptography.HashFunctions
{
    [TestsClass]
    internal class Poly1305_Tests
    {
        [TestMethod]
        public List<TestResult> Poly1305_RFC_7539_Vectors()
        {
            var list = new List<TestResult>();

            foreach (var t in RFC_7539)
            {
                Poly1305 poly = new Poly1305(t.Key);
                poly.Process(t.Message);

                byte[] res = poly.Final();

                list.Add(new TestResult("poly1305", MemOps.Memcmp(t.ExpectedHash, res)));
            }

            return list;
        }

        [TestMethod]
        public List<TestResult> Poly1305_vectors()
        {
            var list = new List<TestResult>();

            foreach (var t in poly1305_vectors)
            {
                Poly1305 poly = new Poly1305(t.Key);
                poly.Process(t.Message);

                byte[] res = poly.Final();

                list.Add(new TestResult("poly1305 vectors", MemOps.Memcmp(t.ExpectedHash, res)));
            }

            return list;
        }

        static List<Vector> RFC_7539 = new List<Vector>
        {
            Vector.RFC("85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b",
                "a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9",
                "43727970746f6772617068696320466f" +
                "72756d2052657365617263682047726f" +
                "7570")
        };


        /// <summary>
        /// https://datatracker.ietf.org/doc/html/draft-nir-cfrg-chacha20-poly1305-06#page-17
        /// </summary>
        static List<Vector> poly1305_vectors = new List<Vector>()
        {
            Vector.RFC("01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                "13 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                "E3 35 94 D7 50 5E 43 B9 00 00 00 00 00 00 00 00" +
                "33 94 D7 50 5E 43 79 CD 01 00 00 00 00 00 00 00" +
                "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
            ,


            Vector.RFC("   01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                "14 00 00 00 00 00 00 00 55 00 00 00 00 00 00 00",
                "E3 35 94 D7 50 5E 43 B9 00 00 00 00 00 00 00 00"+
                "33 94 D7 50 5E 43 79 CD 01 00 00 00 00 00 00 00"+
                "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"+
                "01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
            ,
            Vector.RFC("02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                "FA FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF",
                "FD FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF")
            ,
            Vector.RFC("01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF" + 
                "FB FE FE FE FE FE FE FE FE FE FE FE FE FE FE FE" + 
                "01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01"
                )
            ,
            Vector.RFC("01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                "05 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF" +
                "F0 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF" +
                "11 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                ),
            Vector.RFC("1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0  47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0",
                "45 41 66 9a 7e aa ee 61 e7 08 dc 7c bc c5 eb 62",
                //msg
                "27 54 77 61 73 20 62 72 69 6c 6c 69 67 2c 20 61" +
                "6e 64 20 74 68 65 20 73 6c 69 74 68 79 20 74 6f" +
                "76 65 73 0a 44 69 64 20 67 79 72 65 20 61 6e 64" +
                "20 67 69 6d 62 6c 65 20 69 6e 20 74 68 65 20 77" +
                "61 62 65 3a 0a 41 6c 6c 20 6d 69 6d 73 79 20 77" +
                "65 72 65 20 74 68 65 20 62 6f 72 6f 67 6f 76 65" +
                "73 2c 0a 41 6e 64 20 74 68 65 20 6d 6f 6d 65 20" +
                "72 61 74 68 73 20 6f 75 74 67 72 61 62 65 2e")
            ,
            Vector.RFC("36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                "f3 47 7e 7c d9 54 17 af 89 a6 b8 79 4c 31 0c f0",
                //msg
                "41 6e 79 20 73 75 62 6d 69 73 73 69 6f 6e 20 74" +
                "6f 20 74 68 65 20 49 45 54 46 20 69 6e 74 65 6e" +
                "64 65 64 20 62 79 20 74 68 65 20 43 6f 6e 74 72" +
                "69 62 75 74 6f 72 20 66 6f 72 20 70 75 62 6c 69" +
                "63 61 74 69 6f 6e 20 61 73 20 61 6c 6c 20 6f 72" +
                "20 70 61 72 74 20 6f 66 20 61 6e 20 49 45 54 46" +
                "20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 20" +
                "6f 72 20 52 46 43 20 61 6e 64 20 61 6e 79 20 73" +
                "74 61 74 65 6d 65 6e 74 20 6d 61 64 65 20 77 69" +
                "74 68 69 6e 20 74 68 65 20 63 6f 6e 74 65 78 74" +
                "20 6f 66 20 61 6e 20 49 45 54 46 20 61 63 74 69" +
                "76 69 74 79 20 69 73 20 63 6f 6e 73 69 64 65 72" +
                "65 64 20 61 6e 20 22 49 45 54 46 20 43 6f 6e 74" +
                "72 69 62 75 74 69 6f 6e 22 2e 20 53 75 63 68 20" +
                "73 74 61 74 65 6d 65 6e 74 73 20 69 6e 63 6c 75" +
                "64 65 20 6f 72 61 6c 20 73 74 61 74 65 6d 65 6e" +
                "74 73 20 69 6e 20 49 45 54 46 20 73 65 73 73 69" +
                "6f 6e 73 2c 20 61 73 20 77 65 6c 6c 20 61 73 20" +
                "77 72 69 74 74 65 6e 20 61 6e 64 20 65 6c 65 63" +
                "74 72 6f 6e 69 63 20 63 6f 6d 6d 75 6e 69 63 61" +
                "74 69 6f 6e 73 20 6d 61 64 65 20 61 74 20 61 6e" +
                "79 20 74 69 6d 65 20 6f 72 20 70 6c 61 63 65 2c" +
                "20 77 68 69 63 68 20 61 72 65 20 61 64 64 72 65" +
                "73 73 65 64 20 74 6f")
            ,
            Vector.RFC("0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e",
                "36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e",
                //msg
                "41 6e 79 20 73 75 62 6d 69 73 73 69 6f 6e 20 74" +
                "6f 20 74 68 65 20 49 45 54 46 20 69 6e 74 65 6e" +
                "64 65 64 20 62 79 20 74 68 65 20 43 6f 6e 74 72" +
                "69 62 75 74 6f 72 20 66 6f 72 20 70 75 62 6c 69" +
                "63 61 74 69 6f 6e 20 61 73 20 61 6c 6c 20 6f 72" +
                "20 70 61 72 74 20 6f 66 20 61 6e 20 49 45 54 46" +
                "20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 20" +
                "6f 72 20 52 46 43 20 61 6e 64 20 61 6e 79 20 73" +
                "74 61 74 65 6d 65 6e 74 20 6d 61 64 65 20 77 69" +
                "74 68 69 6e 20 74 68 65 20 63 6f 6e 74 65 78 74" +
                "20 6f 66 20 61 6e 20 49 45 54 46 20 61 63 74 69" +
                "76 69 74 79 20 69 73 20 63 6f 6e 73 69 64 65 72" +
                "65 64 20 61 6e 20 22 49 45 54 46 20 43 6f 6e 74" +
                "72 69 62 75 74 69 6f 6e 22 2e 20 53 75 63 68 20" +
                "73 74 61 74 65 6d 65 6e 74 73 20 69 6e 63 6c 75" +
                "64 65 20 6f 72 61 6c 20 73 74 61 74 65 6d 65 6e" +
                "74 73 20 69 6e 20 49 45 54 46 20 73 65 73 73 69" +
                "6f 6e 73 2c 20 61 73 20 77 65 6c 6c 20 61 73 20" +
                "77 72 69 74 74 65 6e 20 61 6e 64 20 65 6c 65 63" +
                "74 72 6f 6e 69 63 20 63 6f 6d 6d 75 6e 69 63 61" +
                "74 69 6f 6e 73 20 6d 61 64 65 20 61 74 20 61 6e" +
                "79 20 74 69 6d 65 20 6f 72 20 70 6c 61 63 65 2c" +
                "20 77 68 69 63 68 20 61 72 65 20 61 64 64 72 65" +
                "73 73 65 64 20 74 6f")

        };

        class Vector
        {
            public byte[] Key;
            public byte[] Message;
            public byte[] ExpectedHash;

            public Vector(byte[] key, byte[] expectedHash, byte[] msg)
            {
                Key = key;
                Message = msg;
                ExpectedHash = expectedHash;
            }

            public static Vector RFC(string key, string expH, string msg)
            {
                key = key.Replace(":", "").Replace(" ", "");
                msg = msg.Replace(":", "").Replace(" ", "");
                expH = expH.Replace(":", "").Replace(" ", ""); ;


            return new Vector(
                    BinConverter.FromString(key),
                    BinConverter.FromString(expH),
                    BinConverter.FromString(msg));
            }
        }

    }
}
