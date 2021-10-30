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
            cb = new Dictionary<string, AllTests.TaskInfo>();
            string dir = ConfigurationManager.AppSettings.Get("arctium-files");

            if (!Directory.Exists(dir))
            {
                throw new InvalidOperationException("Cannot find directory with test externall files specified in app.config file in RunTests project.");
            }

            Files.SetArctiumFilesPath(dir);
            

            RunTests.Run();
            Console.WriteLine("enter to run old");
            Console.Read();

            RunOld();
        }

        static void RunOld()
        {
            stopwatch.Start();

            

            List<TestResult> allResults = new List<TestResult>();
            List<Task<List<TestResult>>> allTasks = new List<Task<List<TestResult>>>();

            List<Task<List<TestResult>>> shortTasks = AllTests.Run(ProgressCallback);
            List<Task<List<TestResult>>> longTasks = AllTests.RunLong(ProgressCallback);

            allTasks.AddRange(shortTasks);
            allTasks.AddRange(longTasks);

            Task.Factory.StartNew(() => RefreshProgress());

            Task.WaitAll(shortTasks.ToArray());
            List<TestResult> shortResults = shortTasks.SelectMany(task => task.Result).ToList();


            // Task.WaitAll(longTasks.ToArray());
            // List<TestResult> longResults = longTasks.SelectMany(task => task.Result).ToList();
            // ShowResults(longResults);

            stopRefresh = true;

            stopwatch.Stop();

            Console.WriteLine(stopwatch.ElapsedMilliseconds);

            ShowResults(shortResults);
            var all = allTasks.SelectMany(s => s.Result);
        }

        static void ShowResults(List<TestResult> all)
        {
            foreach (var item in all)
            {
                if (!item.Success)
                {
                    Console.WriteLine("Fail: " + item.Test.Name);

                    if (item.Exception != null)
                    {
                        Console.WriteLine("Exception: {0}", item.Exception.Message);
                    }
                }
            }
        }

        static bool stopRefresh = false;

        static void RefreshProgress()
        {
            int i = 0;
            while (!stopRefresh)
            {
                Thread.Sleep(1000);

               Console.Clear();
                Console.WriteLine(i++);
                lock (loc)
                {
                    foreach (var item in cb)
                    {
                        Console.WriteLine($"{item.Key}: {item.Value.CompletedPercent}");
                    }
                }
            }
        }

        static Dictionary<string, AllTests.TaskInfo> cb = new Dictionary<string, AllTests.TaskInfo>();

        static object loc = new object();

        static void ProgressCallback(AllTests.TaskInfo info)
        {
            lock (loc)
            {
                cb[info.TaskName] = info;
            }
        }
    }
}
