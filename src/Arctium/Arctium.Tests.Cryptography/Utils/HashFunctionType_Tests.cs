using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Cryptography.Utils;
using Arctium.Tests.Core;
using Arctium.Tests.Core.Attributes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace Arctium.Tests.Cryptography.Utils
{
    [TestsClass]
    internal class HashFunctionType_Tests
    {
        [TestMethod]
        public List<TestResult> HashFunctionType_AllHashFunctionsInEnumAreDefined()
        {
            var hashFuncsClassName = Assembly.GetAssembly(typeof(HashFunction))
                .GetTypes()
                .Where(c => c.IsClass && !c.IsAbstract && c.IsSubclassOf(typeof(HashFunction)))
                .Select(c => c.Name).ToArray();

            // because need some parameters for constructor
            //var specialCasesToIgnore = new string[]
            //{
            //    nameof(Skein_VAR)
            //};


            var definedNames = Enum.GetNames(typeof(HashFunctionType));

            var h1 = hashFuncsClassName.ToHashSet();
            var h2 = definedNames.ToHashSet();

            h1.SymmetricExceptWith(h2);

            if (h1.Count > 0)
            {
                return h1.Select(x => new TestResult("hashfunctiontype missing (not defined in enum or class not exists): " + x, false)).ToList();
            }

            return new List<TestResult>() { new TestResult("defined hash funcs", true) };
        }
    }
}
