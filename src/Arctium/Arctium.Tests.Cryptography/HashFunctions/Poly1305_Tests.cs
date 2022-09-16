using Arctium.Tests.Core;
using Arctium.Tests.Core.Attributes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Tests.Cryptography.HashFunctions
{
    [TestsClass]
    internal class Poly1305_Tests
    {
        [TestMethod]
        public List<TestResult> Poly1305_Vectors()
        {
            return new List<TestResult>() { new TestResult("poly1305", false) };
        }
    }
}
