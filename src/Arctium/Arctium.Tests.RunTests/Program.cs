using Arctium.Tests.Core;
using Arctium.Tests.Cryptography;
using System;

namespace Arctium.Tests.RunTests
{
    class Program
    {
        static void Main(string[] args)
        {
            // TODO: TEST / Consider other approach of tests
            //
            // Usually I test Hash functions anyway (just in code, create class, compute hash, compare with test vectors etc)
            // to check if it works. For now this is a very simple test automation
            //

            TestResult[] results = AllTests.Run();

            foreach (var item in results)
            {
                if (!item.Success)
                {
                    Console.WriteLine("Fail: " + item.Name);
                }
            }
        }
    }
}
