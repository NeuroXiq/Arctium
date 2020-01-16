Hash functions derive from "HashFunctionBase" which contains basic hashing methods.
Typical hashing schema are below:

```cs
using System;
using System.IO;
using System.Text;
using Arctium.Cryptography.HashFunctions;


namespace DEBUG_ConsoleApplicationForTests
{
    class Program
    {
        static void Main(string[] args)
        {
            HashFunctionBase hashFunction = new SHA224();

            byte[] data1 = new byte[] { 1, 2, 3 };
            byte[] textData = Encoding.ASCII.GetBytes("text data");
            Stream dataStream = new FileStream("C:\\somedata.txt", FileMode.Open);
            byte[] rangeData = new byte[] { 5, 6, 7, 8 };

            //hash some blocks,
            //can mix buffers with streams, all bytes processed in provided orded

            hashFunction.HashBytes(data1);
            hashFunction.HashBytes(textData);
            hashFunction.HashBytes(dataStream);
            hashFunction.HashBytes(rangeData, 1, 2);

            //hash result
            byte[] result = hashFunction.HashFinal();
        }
    }
}

```