using System;
using System.Collections.Generic;
using System.Text;

namespace Arctium.Shared.Helpers.Buffers
{
    public static unsafe class MemDump
    {
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
            int chunksCountInLine = 4,
            int chunkLength = 4,
            string delimiter = " ")
        {
            int linesCount = (buffer.Length / (chunkLength * chunksCountInLine));
            int lastCount = buffer.Length % (chunkLength * chunksCountInLine);

            int currentIndex = 0;

            for (int i = 0; i < linesCount; i++)
            {
                string currentLine = "";
                for (int j = 0; j < chunksCountInLine - 1; j++)
                {

                    // format one chunk (eg. 4 byte )
                    for (int k = 0; k < chunkLength; k++)
                    {
                        currentLine += string.Format("{0:X2}", buffer[currentIndex]);
                        currentIndex++;
                    }

                    // add delimiter after chunk, but only if this is not the last chunk
                    currentLine += delimiter;
                }

                // format last chunk (eg. 4 byte )
                for (int k = 0; k < chunkLength; k++)
                {
                    currentLine += string.Format("{0:X2}", buffer[currentIndex]);
                    currentIndex++;
                }

                // and do not add delimiter

                Console.WriteLine(currentLine);
            }

            string lastLine = "";

            for (int i = 0; i < lastCount; i++)
            {
                for (int j = 0; j < chunkLength && i < lastCount; j++)
                {
                    lastLine += string.Format("{0:X2}", buffer[currentIndex]);
                    currentIndex++;
                    i++;

                    if (j == chunkLength - 1) lastLine += delimiter;

                }
            }

            Console.WriteLine(lastLine);



            //string line = "";
            //string allLines = "";
            //int appendedBytes = 0;

            //for (int i = 0; i < linesCount; i++)
            //{
            //    for (int j = 0; j < lineLength; j++)
            //    {
            //        line += string.Format(format, buffer[j + (i * lineLength)]);

            //        appendedBytes++;
            //        if (appendedBytes % delimiterAfterNthByte == 0)
            //            line += delimiter;
            //    }

            //    allLines += line + "\r\n";
            //    line = "";
            //}

            //string lastLine = "";

            //for (int i = 0; i < lastCount; i++)
            //{
            //    lastLine += string.Format(format, buffer[i + (linesCount * lineLength)]);

            //    appendedBytes++;
            //    if (appendedBytes % delimiterAfterNthByte == 0)
            //        line += delimiter;
            //}

            //allLines += lastLine;

            //Console.WriteLine(allLines);

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
    }
}
