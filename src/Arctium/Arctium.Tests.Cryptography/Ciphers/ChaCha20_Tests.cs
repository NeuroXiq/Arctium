﻿using Arctium.Cryptography.Ciphers.StreamCiphers;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Binary;
using Arctium.Tests.Core;
using Arctium.Tests.Core.Attributes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Tests.Cryptography.Ciphers
{
    [TestsClass]
    internal class ChaCha20_Tests
    {
        [TestMethod]
        public List<TestResult> ChaCha20_RFC_7539()
        {
            List<TestResult> res = new List<TestResult>();
            byte[] output;
            int i = 0;
            foreach (var t in RFC7539Vectors)
            {
                i++;
                var chacha20 = new ChaCha20(t.Key, t.Nonce);
                output = new byte[t.Input.Length];
                chacha20.Encrypt(t.Input, 0, output, 0, t.Input.Length);

                res.Add(new TestResult(i.ToString(), MemOps.Memcmp(t.Output, output)));
            }

            return res;
        }

        static List<Vector> RFC7539Vectors = new List<Vector>()
        {
            Vector.R("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", // key
                "00:00:00:00:00:00:00:4a:00:00:00:00", // nonce
                "4c616469657320616e642047656e746c" + // plaintext sunscreen
                "656d656e206f662074686520636c6173" +
                "73206f66202739393a20496620492063" +
                "6f756c64206f6666657220796f75206f" +
                "6e6c79206f6e652074697020666f7220" +
                "746865206675747572652c2073756e73" +
                "637265656e20776f756c642062652069" +
                "742e",
                "6e2e359a2568f98041ba0728dd0d6981" + // cipher text expected
                "e97e7aec1d4360c20a27afccfd9fae0b" +
                "f91b65c5524733ab8f593dabcd62b357" +
                "1639d624e65152ab8f530c359f0861d8" +
                "07ca0dbf500d6a6156a38e088a22b65e" +
                "52bc514d16ccf806818ce91ab7793736" +
                "5af90bbf74a35be6b40b8eedf2785e42" +
                "874d")
        };

    class Vector
    {
        public byte[] Key;
        public byte[] Nonce;
        public byte[] Input;
        public byte[] Output;

        public Vector(string key, string nonce)
        {
        }

        public Vector(byte[] key, byte[] nonce, byte[] input, byte[] output)
        {
            Key = key;
            Nonce = nonce;
            Input = input;
            Output = output;
        }   


        public static Vector R(string key, string nonce, string input, string output)
        {
            if (key.Contains(':')) key = key.Replace(":", "");
            if (nonce.Contains(':')) nonce = nonce.Replace(":", "");
            if (input.Contains(':')) input = input.Replace(":", "");
            if (output.Contains(':')) output = output.Replace(":", "");

            return new Vector(
                BinConverter.FromString(key),
                BinConverter.FromString(nonce),
                BinConverter.FromString(input),
                BinConverter.FromString(output));
        }
        }
    }
}
