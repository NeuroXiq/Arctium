using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Shared.Helpers.Binary;
using Arctium.Tests.Core;
using Arctium.Tests.Core.Attributes;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Arctium.Tests.Cryptography.HashFunctions
{
    [TestsClass]
    internal class RadioGatun_Tests
    {
        private List<HashFunctionTest> RadioGatun64Tests;

        public RadioGatun_Tests()
        {
            LoadRadioGatun64Tests();
        }

        [TestMethod]
        public List<TestResult> RadioGatun64_Tests()
        {
            RadioGatun64 radioGatun64 = new RadioGatun64();
            
            return ExecuteHashFunctionTests.RunTests(radioGatun64, RadioGatun64Tests);
        }

        private void LoadRadioGatun64Tests()
        {
            RadioGatun64Tests = new List<HashFunctionTest>();
            var allLines = File.ReadAllLines(Files.HashFunctions.RadioGatun64TestVectors);

            for (int i = 0; i < allLines.Length; i+=3)
            {
                string name = allLines[i + 0];
                string inputString = allLines[i + 1];
                string expectedHashAsString = allLines[i + 2];

                byte[] inputBytes = Encoding.ASCII.GetBytes(inputString);
                byte[] expectedHashBytes = BinConverter.FromString(expectedHashAsString);

                name = name.Length > 64 ? name.Substring(0, 64) + "[...]" : name;

                RadioGatun64Tests.Add(new HashFunctionTest(inputBytes, expectedHashBytes, name));
            }
        }
    }
}
