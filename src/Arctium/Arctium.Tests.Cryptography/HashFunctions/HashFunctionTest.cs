using System;
using System.Collections.Generic;
using System.Text;

namespace Arctium.Tests.Cryptography.HashFunctions
{
    class HashFunctionTest
    {
        public byte[] InputBytes;

        public byte[] ExpectedResultHash;

        public HashFunctionTest()
        {
        }

        public HashFunctionTest(byte[] input, byte[] expectedOutput) 
        {
            InputBytes = input;
            ExpectedResultHash = expectedOutput;
        }
    }
}
