using Arctium.Connection.Tls.Protocol.RecordProtocol;
using System;
using System.Text;

namespace Arctium.Connection.Tls.Crypto
{
    class PseudoRandomFunction
    {
        public byte[] Prf(byte[] secret, string label, byte[] seed, int length)
        {
            byte[] labelBytes = GetStringBytes(label);

            byte[] secretLeft, secretRight;
            SplitSecret(secret, out secretLeft, out secretRight);

            DataExpansionFunction md5Expansion = new DataExpansionFunction(MACAlgorithm.MD5);
            DataExpansionFunction sha1Expansion = new DataExpansionFunction(MACAlgorithm.SHA);

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

        private byte[] GetStringBytes(string label)
        {
            return Encoding.ASCII.GetBytes(label);
        }

        private byte[] Join(byte[] clientRandom, byte[] serverRandom)
        {
            byte[] joined = new byte[clientRandom.Length + serverRandom.Length];
            Array.Copy(clientRandom, 0, joined, 0, clientRandom.Length);
            Array.Copy(serverRandom, 0, joined, clientRandom.Length, serverRandom.Length);

            return joined;
        }
    }
}
