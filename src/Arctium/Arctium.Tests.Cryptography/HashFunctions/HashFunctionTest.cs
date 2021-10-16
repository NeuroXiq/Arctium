using Arctium.Tests.Core;
using System.IO;

namespace Arctium.Tests.Cryptography.HashFunctions
{
    public class HashFunctionTest : Test
    {
        public enum InputToUse
        {
            InputBytes,
            Stream
        }

        public InputToUse UseInput;

        public RepeatStream Stream;

        public byte[] InputBytes;

        public byte[] ExpectedResultHash;

        public HashFunctionTest()
        {
        }

        public HashFunctionTest(byte[] input, byte[] expectedOutput) : this(input, expectedOutput, null)
        {
        }

        public HashFunctionTest(RepeatStream stream, byte[] expectedOutput, string name)
        {
            Name = name;
            Stream = stream;
            ExpectedResultHash = expectedOutput;
            UseInput = InputToUse.Stream;
        }

        public HashFunctionTest(byte[] input, byte[] expectedOutput, string name)
        {
            Name = name;
            InputBytes = input;
            ExpectedResultHash = expectedOutput;
            UseInput = InputToUse.InputBytes;
        }
    }
}
