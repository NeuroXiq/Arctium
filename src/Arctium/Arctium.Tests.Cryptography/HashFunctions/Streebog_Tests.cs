using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Shared.Helpers.Binary;
using Arctium.Tests.Core;
using Arctium.Tests.Core.Attributes;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Tests.Cryptography.HashFunctions
{
    [TestsClass]
    internal class Streebog_Tests
    {

        [TestMethod]
        public List<TestResult> Streebog_512Tests()
        {
            List<HashFunctionTest> tests = LoadFromFile(Files.HashFunctions.Streebog512TestVectors, "512");

            Streebog_512 streebog512 = new Streebog_512();

            return ExecuteHashFunctionTests.RunTests(streebog512, tests);
        }

        [TestMethod]
        public List<TestResult> Streebog_256Tests()
        {
            List<HashFunctionTest> tests = LoadFromFile(Files.HashFunctions.Streebog256TestVectors, "256");

            Streebog_256 streebog256 = new Streebog_256();

            return ExecuteHashFunctionTests.RunTests(streebog256, tests);
        }

        private static List<HashFunctionTest> LoadFromFile(string fileName, string version)
        {
            string[] allLines = File.ReadAllLines(fileName);
            List<HashFunctionTest> tests = new List<HashFunctionTest>();

            foreach (var line in allLines)
            {
                string[] splitLine = line.Split("=");
                byte[] input = Encoding.ASCII.GetBytes(splitLine[0]);
                byte[] expectedHash = BinConverter.FromString(splitLine[1]);

                tests.Add(new HashFunctionTest(input, expectedHash, "Streebog " + version + " inputlen: " + input.Length));
            }

            return tests;
        }
    }
}
