using Arctium.Tests.Core;
using Arctium.Tests.Cryptography;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Arctium.Tests.RunTests
{
    class Program
    {
        static Stopwatch stopwatch = new Stopwatch();

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
            

            RunTests.Run(args);
            Console.WriteLine("FINISHED TESTS");
            Console.WriteLine("enter to to exit");
            Console.Read();
        }
    }
}
