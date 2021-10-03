using Arctium.Tests.Core;
using Arctium.Tests.Cryptography;
using System;
using System.Configuration;
using System.IO;

namespace Arctium.Tests.RunTests
{
    class Program
    {
        static void Main(string[] args)
        {
            // TODO: TEST / Consider other approach of tests
            //
            // to check if it works. For now this is a very simple test automation
            //

            string dir = ConfigurationManager.AppSettings.Get("arctium-files");

            if (!Directory.Exists(dir))
            {
                throw new InvalidOperationException("Cannot find directory with test externall files specified in app.config file in RunTests project.");
            }

            Files.SetArctiumFilesPath(dir);
            TestResult[] results = AllTests.RunShortTests();

            foreach (var item in results)
            {
                if (!item.Success)
                {
                    Console.WriteLine("Fail: " + item.Name);

                    if (item.Exception != null)
                    {
                        Console.WriteLine("Exception: {0}", item.Exception.Message);
                    }
                }
            }
        }
    }
}
