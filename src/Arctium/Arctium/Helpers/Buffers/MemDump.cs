using System;
using System.Collections.Generic;
using System.Text;

namespace Arctium.Shared.Helpers.Buffers
{
    [Obsolete("MemDump is invoked")]
    public static unsafe class MemDump
    {
        public static void HexDump(ulong value)
        {
            Console.WriteLine("{0:X16}", value);
        }


        public static void HexDump(ulong[] buffer,
            int offset = 0,
            int length = -1,
            int chinksCountInLine = 4,
            int chinkLength = 4,
            string delimiter = " ")
        {
            int len = length == -1 ? buffer.Length : length;
            byte[] helper = new byte[len * 8];

            for (int i = 0; i < len; i++)
            {
                MemMap.ToBytes1ULongBE(buffer[i + offset], helper, (i) * 8);
            }

            HexDump(helper, 0, helper.Length, chinksCountInLine, chinkLength, delimiter);
        }

        /// <summary>
        /// Writes formatter byte array to the console output as a hexdump
        /// Useful in debugging
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="lineLength"></param>
        /// <param name="delimiterAfterNthByte"></param>
        /// <param name="delimiter"></param>
        /// <param name="format"></param>
        public static void HexDump(byte[] buffer,
            int offset = 0,
            int length = -1,
            int chunksCountInLine = 4,
            int chunkLength = 4,
            string delimiter = " ")
        {
            if (length == -1) length = buffer.Length;

            StringBuilder result = new StringBuilder(buffer.Length);

            int writtedBytes = 0;

            while (writtedBytes < length)
            {
                int remaining = length - writtedBytes;
                int maxTake =  remaining >= chunkLength ? chunkLength : remaining;

                for (int i = 0; i < maxTake; i++) result.Append(string.Format("{0:X2}", buffer[i + offset + writtedBytes]));
                writtedBytes += maxTake;

                if (maxTake == chunkLength)
                {
                    if ((writtedBytes / chunkLength) % chunksCountInLine == 0) result.AppendLine();
                    else result.Append(delimiter);
                }
            }

            Console.WriteLine(result.ToString());
        }

        public static void HexDump(byte* p, int length, int groupLength = -1)
        {
            for (int i = 0; i < length; i++)
            {
                Console.Write("{0:X2}", p[i]);

                if ((i + 1) % groupLength == 0) Console.Write(" ");
            }
        }

        public static void HexDump(uint* ptr, int length, int width = 4)
        {
            for (int i = 0; i < length; i++)
            {
                Console.Write("{0:X8} ", ptr[i]);

                if ((i + 1) % width == 0) Console.WriteLine();
            }
        }

        public static void HexDump(ulong* src, int count, int ulongsInLine)
        {
            for (int i = 0; i < count; i++)
            {
                Console.Write("{0:X8} ", src[i]);
                if ((i + 1) % ulongsInLine == 0) Console.WriteLine();
            }
            Console.WriteLine();
        }

        public static void HexDump(uint[] memory)
        {
            for (int i = 0; i < memory.Length; i++)
            {
                if (i != 0 && i % 4 == 0) Console.WriteLine();
                Console.Write("{0:X8} ", memory[i]);
            }

            Console.WriteLine();
            Console.WriteLine();
        }
    }
}
