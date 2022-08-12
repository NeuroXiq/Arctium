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
using System.Configuration;
using System.Text.RegularExpressions;

namespace Arctium.Tests.RunTests
{
    public class RunTests
    {
        public class FinishedTestsInfo
        {
            public string ClassName;
            public string MethodName;
            public List<TestResult> Results;

            public FinishedTestsInfo(string className, string methodName, List<TestResult> results)
            {
                ClassName = className;
                MethodName = methodName;
                Results = results;
            }
        }

        public class ConsoleOutput
        {
            object _lock = new object();
            int appendFinishedTestCursorTop = 4;
            public int totalSuccess = 0;
            public int totalFail = 0;
            private string displayFormat;
            List<TestResult> allTests;

            public int TotalTests = 0;
            int finishedTests = 0;

            public ConsoleOutput(string displayFormat)
            {
                this.displayFormat = displayFormat;
                allTests = new List<TestResult>();
            }

            public void ShowFinishedTestResults(FinishedTestsInfo info)
            {
                Monitor.Enter(_lock);

                finishedTests++;
                allTests.AddRange(info.Results);

                foreach (var t in info.Results)
                {
                    if (t.Success)
                    {
                        totalSuccess++;
                    }
                    else
                    {
                        totalFail++;
                    }
                }

                AppendFinishedTestsList(info);

                Monitor.Exit(_lock);
            }

            private void AppendFinishedTestsList(FinishedTestsInfo info)
            {
                if (displayFormat == "allTests")
                {
                    foreach (var t in info.Results)
                    {
                        string m = t.Name;
                        // appendFinishedTestCursorTop++;
                        // Console.CursorTop = appendFinishedTestCursorTop - 1;

                        if (!t.Success)
                        {
                            if (t.Exception != null)
                            {
                                m += "(" + t.Exception.Message + ")";
                            }

                            m = "FAIL: " + m;
                            Console.ForegroundColor = ConsoleColor.DarkMagenta;
                        }

                        Console.WriteLine(m);

                        Console.ForegroundColor = ConsoleColor.Gray;
                    }
                }
                else if (displayFormat == "liveSummary")
                {
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
                    Console.Write(string.Format("completed: {0} / {1} ({2:0.00}%)", finishedTests, TotalTests, 100 * ((double)finishedTests / TotalTests)));
                }
                else if (displayFormat == "class-summary")
                {

                }
                else throw new Exception("invalid value for tests display format");
            }
        }

        public static ConsoleOutput consoleOutput = new ConsoleOutput(ConfigurationManager.AppSettings.Get("console-tests-display-format"));
        static List<Task> tasks = new List<Task>();
        private static string filterClassRegex;

        public static void Run(string[] args)
        {
            if (args.Length > 0) filterClassRegex = args[0];

            var tests = FindTestClasses();
            var filteredTests = FilterTests(tests);

            foreach (var testClass in filteredTests)
            {
                RunTestsFromClass(testClass);
            }

            Task.WaitAll(tasks.ToArray());
            Console.WriteLine("- END -");
        }

        static List<Type> FilterTests(List<Type> tests)
        {
            string filter = filterClassRegex;

            if (!string.IsNullOrEmpty(filter))
            {
                return tests.Where(t => Regex.Match(t.Name, filter).Success).ToList();
            }

            return tests;
        }

        static List<Type> FindTestClasses()
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

            return testClasses;
        }

        private static void RunTestsFromClass(Type testClass)
        {
            var members = testClass.GetMethods().Where(method => method.GetCustomAttributes(typeof(TestMethodAttribute)).Any()).ToList();
            members = members.OrderBy(method => method.GetCustomAttribute<TestMethodAttribute>().ExpectedDurationInSeconds).ToList();
            var instance = Activator.CreateInstance(testClass);
            // List<TestResult> testResults = new List<TestResult>();
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
                        // testResults.AddRange(res);

                        var finishedInfo = new FinishedTestsInfo(meth.DeclaringType.Name, meth.Name, res);
                        consoleOutput.ShowFinishedTestResults(finishedInfo);
                    }
                }, g);

                tasks.Add(task);
            }
        }

        private static List<List<MethodInfo>> SplitToEqualSizeGroups(List<MethodInfo> methods, int groupsCount)
        {
            List<List<MethodInfo>> results = new List<List<MethodInfo>>();
            int itemsInGroup = (methods.Count / groupsCount) + 1;
            itemsInGroup = itemsInGroup < 1 ? 1 : itemsInGroup;

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

            //for (int i = 0; i < remainder; i++)
            //{
            //    results[results.Count - 1].Add(methods[methods.Count - 1 - i]);
            //}

            return results;
        }

        static void ReferenceAssemblies()
        {
            // getreferenceassemblies doesn't work without reference in code
            PKCSv2_2API_Tests t;
        }
    }
}
