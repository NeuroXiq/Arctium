using System;

namespace Arctium.Connection.Tls.Buffers
{
    class BufferTools
    {

        ///<summary>Concatenate byte arrays in order given in parameter</summary>
        public static byte[] Join(params byte[][] buffers)
        {
            int totalLength = 0;
            foreach (byte[] buffer in buffers)
                totalLength += buffer.Length;

            byte[] result = new byte[totalLength];
            int nextOffset = 0;

            foreach (byte[] buffer in buffers)
            {
                Buffer.BlockCopy(buffer, 0, result, nextOffset, buffer.Length);
                nextOffset += buffer.Length;
            }

            return result;
        }

        public static bool IsContentEqual(byte[] b1, byte[] b2)
        {
            if (b1 == null) throw new NullReferenceException("b1");
            if (b2 == null) throw new NullReferenceException("b2");

            if (b1.Length != b2.Length) return false;
            for (int i = 0; i < b1.Length; i++)
            {
                if (b1[i] != b2[i]) return false;
            }

            return true;
        }

        public static byte[] Substring(byte[] buffer, int offset, int length)
        {
            if (length == 0) return new byte[0];
            byte[] substring = new byte[length];

            Buffer.BlockCopy(buffer, offset, substring, 0, length);

            return substring;
        }
    }
}
