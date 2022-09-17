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

        static List<Vector> RFC_7539 = new List<Vector>
        {
            Vector.RFC("85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b",
                "a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9",
                "43727970746f6772617068696320466f" +
                "72756d2052657365617263682047726f" +
                "7570")
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
                key = key.Replace(":", "");
                msg = msg.Replace(":", "");
                expH = expH.Replace(":", ""); ;


            return new Vector(
                    BinConverter.FromString(key),
                    BinConverter.FromString(expH),
                    BinConverter.FromString(msg));
            }
        }

    }
}
