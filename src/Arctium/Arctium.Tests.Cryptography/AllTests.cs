﻿using Arctium.Tests.Core;
using Arctium.Tests.Cryptography.HashFunctions.SHA3;
using System.Collections.Generic;

namespace Arctium.Tests.Cryptography
{
    public class AllTests
    {
        public static TestResult[] Run()
        {
            List<TestResult> results = new List<TestResult>();

            results.AddRange(SHA3_Tests.Run());

            return results.ToArray();
        }
    }
}
