using Arctium.Connection.Tls.Buffers;
using Arctium.Connection.Tls.CryptoConfiguration;
using System;
using System.Text;

namespace Arctium.Connection.Tls.CryptoFunctions
{
    class PRF
    {

        public static byte[] Prf12(byte[] secret, string label, byte[] seed, int length)
        {
            DataExpansionFunction def = new DataExpansionFunction(HashAlgorithmType.SHA256);

            byte[] phashSeed = BufferTools.Join(GetStringBytes(label), seed);
            return def.Generate(secret, phashSeed, length);
        }

        public byte[] Prf11(byte[] secret, string label, byte[] seed, int length)
        {
            byte[] labelBytes = GetStringBytes(label);

            byte[] secretLeft, secretRight;
            SplitSecret(secret, out secretLeft, out secretRight);

            DataExpansionFunction md5Expansion = new DataExpansionFunction(HashAlgorithmType.MD5);
            DataExpansionFunction sha1Expansion = new DataExpansionFunction(HashAlgorithmType.SHA1);

            byte[] md5Stream = md5Expansion.Generate(secretLeft, Join(labelBytes, seed), length);
            byte[] sha1Stream = sha1Expansion.Generate(secretRight, Join(labelBytes, seed), length);

            byte[] result = XorStreams(md5Stream, sha1Stream);

            return result;
        }

        private byte[] XorStreams(byte[] md5Stream, byte[] sha1Stream)
        {
            byte[] result = new byte[md5Stream.Length];

            for (int i = 0; i < result.Length; i++)
            {
                result[i] = (byte)(md5Stream[i] ^ sha1Stream[i]);
            }

            return result;
        }

        private void SplitSecret(byte[] secret, out byte[] s1, out byte[] s2)
        {
            int length = (secret.Length) / 2;
            int delta = secret.Length % 2;

            s1 = new byte[length + delta];
            s2 = new byte[length + delta];

            for (int i = 0; i < length + delta; i++)
            {
                s1[i] = secret[i];
                s2[i] = secret[i + length];
            }
        }

        private static byte[] GetStringBytes(string label)
        {
            return Encoding.ASCII.GetBytes(label);
        }

        private byte[] Join(byte[] left, byte[] right)
        {
            byte[] joined = new byte[left.Length + right.Length];
            Array.Copy(left, 0, joined, 0, left.Length);
            Array.Copy(right, 0, joined, left.Length, right.Length);

            return joined;
        }
    }
}
