using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using Arctium.Tests.Standards;
using Arctium.Tests.Standards.PKCS1;
using Arctium.Tests.Core.Attributes;
using Arctium.Tests.Core;
using System.Threading;
using System.Threading.Tasks;

namespace Arctium.Tests.RunTests
{
    public class RunTests
    {
        class ConsoleOutput
        {
            object _lock = new object();
            int testfailcursorline = 4;
            int totalSuccess = 0;
            int totalFail = 0;
            List<TestResult> allTests;

            public int TotalTests = 0;
            int finishedTests = 0;

            public ConsoleOutput()
            {
                allTests = new List<TestResult>();
            }

            public void ShowFinishedTestResults(List<TestResult> results)
            {
                Monitor.Enter(_lock);

                finishedTests++;
                allTests.AddRange(results);
                List<TestResult> fails = new List<TestResult>();

                foreach (var t in results)
                {
                    if (t.Success) { totalSuccess++; continue; }

                    totalFail++;
                    fails.Add(t);
                }

                UpdateStatusInConsoleWindow(fails);

                Monitor.Exit(_lock);
            }

            private void UpdateStatusInConsoleWindow(List<TestResult> fails)
            {
                foreach (var t in fails)
                {
                    string m = t.Name;

                    if (t.Exception != null)
                    {
                        m += "(" + t.Exception.Message + ")";
                    }

                    Console.CursorTop = testfailcursorline;
                    testfailcursorline++;
                    Console.WriteLine(m);
                }

                for (int i = 0; i < 3; i++)
                {
                    Console.SetCursorPosition(0, i);
                    for (int j = 0; j < 20; j++) Console.Write(" ");
                }

                Console.SetCursorPosition(0, 0);
                Console.Write("success: " + totalSuccess);
                Console.SetCursorPosition(0, 1);
                Console.Write("fail: " + totalFail);
                Console.SetCursorPosition(0, 2);
                Console.Write(string.Format("completed: {0} / {1} ({2:0.00}%)", finishedTests, TotalTests, 100*((double)finishedTests / TotalTests)));
            }
        }

        static ConsoleOutput consoleOutput = new ConsoleOutput();
        static List<Task> tasks = new List<Task>();

        public static void Run()
        {
            FindTests();
            Task.WaitAll(tasks.ToArray());
            Console.WriteLine("- END -");
        }

        static void FindTests()
        {
            var testAssemblies = typeof(RunTests).Assembly.GetReferencedAssemblies().Where(asm => asm.Name.StartsWith("Arctium."));
            var assemblies = testAssemblies.Select(asm => Assembly.Load(asm));
            var allTypes = assemblies.SelectMany(asm => asm.GetTypes());
            var testClasses = new List<Type>();

            foreach (Type type in allTypes)
            {
                if (type.GetCustomAttribute<TestsClassAttribute>() != null)
                {
                    testClasses.Add(type);
                }
            }

            foreach (var testClass in testClasses)
            {
                RunTestsFromClass(testClass);
            }
        }

        private static void RunTestsFromClass(Type testClass)
        {
            var members = testClass.GetMethods().Where(method => method.GetCustomAttributes(typeof(TestMethodAttribute)).Any()).ToList();
            members = members.OrderBy(method => method.GetCustomAttribute<TestMethodAttribute>().ExpectedDurationInSeconds).ToList();
            var instance = Activator.CreateInstance(testClass);
            List<TestResult> testResults = new List<TestResult>();
            List<List<MethodInfo>> groups = SplitToEqualSizeGroups(members, 4);
            consoleOutput.TotalTests += members.Count;

            foreach (var g in groups)
            {
                var task = Task.Factory.StartNew((group) =>
                {
                    // Thread.CurrentThread.Priority = ThreadPriority.Highest;
                    foreach (var meth in (List<MethodInfo>)group)
                    {
                        object objResults = meth.Invoke(instance, new object[0]);
                        List<TestResult> res = (List<TestResult>)objResults;
                        testResults.AddRange(res);
                        ShowResulsts(res);
                    }
                }, g);

                tasks.Add(task);
            }
        }

        private static List<List<MethodInfo>> SplitToEqualSizeGroups(List<MethodInfo> methods, int groupsCount)
        {
            List<List<MethodInfo>> results = new List<List<MethodInfo>>();
            int itemsInGroup = methods.Count / groupsCount;
            itemsInGroup = itemsInGroup < 1 ? 1 : itemsInGroup;
            int remainder = methods.Count % groupsCount;

            for (int i = 0; i < groupsCount; i++)
            {
                List<MethodInfo> group = new List<MethodInfo>();
                int idx = (itemsInGroup * i);

                for (int j = 0; j < itemsInGroup && (idx + j) < methods.Count; j++)
                {
                    group.Add(methods[idx + j]);
                }

                results.Add(group);
            }

            for (int i = 0; i < remainder; i++)
            {
                results[results.Count - 1].Add(methods[methods.Count - 1 - i]);
            }

            return results;
        }

        private static void ShowResulsts(List<TestResult> results)
        {
            consoleOutput.ShowFinishedTestResults(results);
        }

        static void ReferenceAssemblies()
        {
            // getreferenceassemblies doesn't work without reference in code
            PKCSv2_2API_Tests t;
        }
    }
}
