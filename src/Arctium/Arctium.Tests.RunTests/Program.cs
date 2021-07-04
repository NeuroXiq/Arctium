using Arctium.Tests.Core;
using Arctium.Tests.Cryptography;
using System;

namespace Arctium.Tests.RunTests
{
    class Program
    {
        static void Main(string[] args)
        {
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
