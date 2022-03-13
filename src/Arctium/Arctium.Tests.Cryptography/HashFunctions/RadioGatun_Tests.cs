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
        private List<HashFunctionTest> RadioGatun32Tests;

        public RadioGatun_Tests()
        {
            LoadRadioGatunTests();
        }

        [TestMethod]
        public List<TestResult> RadioGatun64_Tests()
        {
            RadioGatun64 radioGatun64 = new RadioGatun64();
            
            return ExecuteHashFunctionTests.RunTests(radioGatun64, RadioGatun64Tests);
        }

        [TestMethod]
        public List<TestResult> RadioGatun32_Tests()
        {
            RadioGatun32 radioGatun32 = new RadioGatun32();

            return ExecuteHashFunctionTests.RunTests(radioGatun32, RadioGatun32Tests);
        }

        private void LoadRadioGatunTests()
        {
            var allLines64 = File.ReadAllLines(Files.HashFunctions.RadioGatun64TestVectors);
            var allLines32 = File.ReadAllLines(Files.HashFunctions.RadioGatun32TestVectors);

            RadioGatun64Tests = Parse(allLines64);
            RadioGatun32Tests = Parse(allLines32);
        }

        private List<HashFunctionTest> Parse(string[] allLines)
        {
            List<HashFunctionTest> tests = new List<HashFunctionTest>();

            for (int i = 0; i < allLines.Length; i += 3)
            {
                string name = allLines[i + 0];
                string inputString = allLines[i + 1];
                string expectedHashAsString = allLines[i + 2];

                byte[] inputBytes = Encoding.ASCII.GetBytes(inputString);
                byte[] expectedHashBytes = BinConverter.FromString(expectedHashAsString);

                name = name.Length > 64 ? name.Substring(0, 64) + "[...]" : name;

                tests.Add(new HashFunctionTest(inputBytes, expectedHashBytes, name));
            }

            return tests;
        }
    }
}
