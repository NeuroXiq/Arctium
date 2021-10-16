using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Tests.Core;
using Arctium.Tests.Cryptography.Ciphers;
using Arctium.Tests.Cryptography.HashFunctions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Arctium.Tests.Cryptography
{
    public class AllTests
    {
        public class TaskInfo
        {
            public string TaskName;
            public int CompletedPercent;

            public TaskInfo(string name, int completedPercent)
            {
                TaskName = name;
                CompletedPercent = completedPercent;
            }
        }

        public static List<Task<List<TestResult>>> Run(Action<TaskInfo> progressCallback)
        {
            List<TestResult> results = new List<TestResult>();
            List<Task<List<TestResult>>> tasks = new List<Task<List<TestResult>>>();

            var allToRun = new List<TaskItem>();
            var hf = HashFunctionsShort();
            var ciph = CipherTests();

            foreach (var item in hf)
            {
                TaskItem i = new TaskItem();

                i.FuncToRun = () =>
                {
                    var result = ExecuteHashFunctionTests.RunTests(item.HashFunction, item.Tests);
                    i.CompletedCallback?.Invoke(100);

                    return result;
                };

                allToRun.Add(i);
            }

            foreach (var item in ciph)
            {
                TaskItem i = new TaskItem();

                i.FuncToRun = () =>
                {
                    var r = item();
                    i.CompletedCallback?.Invoke(100);

                    return r;
                };

                allToRun.Add(i);
            }

            int taskCount = 4;
            var groups = SplitToMultiple(allToRun, taskCount);

            tasks.AddRange(RunTasks(groups, progressCallback, "Short"));
            
            return tasks;
        }

        public static List<Task<List<TestResult>>> RunLong(Action<TaskInfo> progressCallback)
        {
            List<Task<List<TestResult>>> results = new List<Task<List<TestResult>>>();

            var torun = ToRunLong();
            var itemsToRun = new List<TaskItem>();

            foreach (var tr in torun)
            {
                TaskItem i = new TaskItem();
                i.FuncToRun = () =>
                {
                    int totalRead = 0;
                    int totalBytesCount = tr.Tests.Sum(t => t.Stream.RepeatStreamRepeatCount);

                    foreach (var test in tr.Tests)
                    {
                        test.Stream.SetDataReadedCallback((readCount) =>
                        {
                            totalRead += readCount;
                            int percent = (int)(100 * (double)totalRead / test.Stream.RepeatStreamRepeatCount);
                            i.CompletedCallback?.Invoke(percent);
                        });
                    }

                    var res = ExecuteHashFunctionTests.RunTests(tr.HashFunction, tr.Tests);

                    return res;
                };

                itemsToRun.Add(i);
            }


            int taskCount = 4;
            var groups = SplitToMultiple(itemsToRun, taskCount);
            results.AddRange(RunTasks(groups, progressCallback, "Long"));

            return results;
        }

        static List<Task<List<TestResult>>> RunTasks(List<List<TaskItem>> groupsToRun, Action<TaskInfo> progressCallback, string groupname)
        {
            List<Task<List<TestResult>>> tasks = new List<Task<List<TestResult>>>();

            for (int i = 0; i < groupsToRun.Count; i++)
            {
                var t = Task.Factory.StartNew<List<TestResult>>((argAsObj) =>
                {
                    Thread.CurrentThread.Priority = ThreadPriority.Highest;
                    arg items = argAsObj as arg;
                    int totalPercent = items.items.Count * 100;
                    int[] completedPerFunc = new int[items.items.Count];

                    List<TestResult> results = new List<TestResult>();

                    for (int j = 0; j < items.items.Count; j++)
                    {
                        TaskItem item = items.items[j];

                        item.CompletedCallback = (nextProgressInPercent) =>
                        {
                            completedPerFunc[j] = nextProgressInPercent;
                            int totalCompleted = (int)(100 * (double)completedPerFunc.Sum(q => q) / totalPercent);
                            progressCallback(new TaskInfo(groupname + "/" + items.i.ToString(), totalCompleted));
                        };

                        results.AddRange(item.FuncToRun());
                    }

                    return results;

                }, new arg(groupsToRun[i], i));

                tasks.Add(t);
            }

            return tasks;
        }

        static List<List<TaskItem>> SplitToMultiple(List<TaskItem> torun, int taskCount)
        {
            int chunk = torun.Count / taskCount;
            chunk = chunk == 0 ? 1 : chunk;
            int start = 0, end = 0;

            List<List<TaskItem>> groups = new List<List<TaskItem>>();

            for (int i = 0; i < taskCount; i++)
            {
                List<TaskItem> items = new List<TaskItem>();
                start = i * chunk;

                for (int j = start; j < (chunk * (i + 1)) && (j < torun.Count); j++)
                {
                    items.Add(torun[j]);
                }

                groups.Add(items);
            }

            return groups;
        }

        class arg
        {
            public List<TaskItem> items;
            public int i;

            public arg(List<TaskItem> items, int i)
            {
                this.i = i;
                this.items = items;
            }
        }

        static List<Func<List<TestResult>>> CipherTests()
        {
            return new List<Func<List<TestResult>>>
            {
                () => ThreefishTests.Run()
            };
        }

        static List<HashFunctionWithTests> HashFunctionsShort()
        {
            return new List<HashFunctionWithTests>
            {
                new HashFunctionWithTests(new JH_224(), JHTests.Short224),
                new HashFunctionWithTests(new JH_256(), JHTests.Short256),
                new HashFunctionWithTests(new JH_384(), JHTests.Short384),
                new HashFunctionWithTests(new JH_512(), JHTests.Short512),

                new HashFunctionWithTests(new SHA3_224(), SHA3_Tests.Short224),
                new HashFunctionWithTests(new SHA3_256(), SHA3_Tests.Short256),
                new HashFunctionWithTests(new SHA3_384(), SHA3_Tests.Short384),
                new HashFunctionWithTests(new SHA3_512(), SHA3_Tests.Short512),

                new HashFunctionWithTests(new Skein_VAR(Skein.InternalStateSize.Bits_256, 224), Skein_Tests.Short256_224),
                new HashFunctionWithTests(new Skein_256(), Skein_Tests.Short256_256),
                new HashFunctionWithTests(new Skein_VAR(Skein.InternalStateSize.Bits_256, 384), Skein_Tests.Short256_384),
                new HashFunctionWithTests(new Skein_VAR(Skein.InternalStateSize.Bits_256, 512), Skein_Tests.Short256_512),
                new HashFunctionWithTests(new Skein_VAR(Skein.InternalStateSize.Bits_256, 1024), Skein_Tests.Short256_1024),
                new HashFunctionWithTests(new Skein_VAR(Skein.InternalStateSize.Bits_512, 224), Skein_Tests.Short512_224),
                new HashFunctionWithTests(new Skein_VAR(Skein.InternalStateSize.Bits_512, 256), Skein_Tests.Short512_256),
                new HashFunctionWithTests(new Skein_VAR(Skein.InternalStateSize.Bits_512, 384), Skein_Tests.Short512_384),
                new HashFunctionWithTests(new Skein_512(), Skein_Tests.Short512_512),
                new HashFunctionWithTests(new Skein_VAR(Skein.InternalStateSize.Bits_512, 1024), Skein_Tests.Short512_1024),
                new HashFunctionWithTests(new Skein_VAR(Skein.InternalStateSize.Bits_1024, 224), Skein_Tests.Short1024_224),
                new HashFunctionWithTests(new Skein_VAR(Skein.InternalStateSize.Bits_1024, 256), Skein_Tests.Short1024_256),
                new HashFunctionWithTests(new Skein_VAR(Skein.InternalStateSize.Bits_1024, 384), Skein_Tests.Short1024_384),
                new HashFunctionWithTests(new Skein_VAR(Skein.InternalStateSize.Bits_1024, 512), Skein_Tests.Short1024_512),
                new HashFunctionWithTests(new Skein_1024(), Skein_Tests.Short1024_1024),

                new HashFunctionWithTests(new BLAKE2b_512(), BLAKE2b_512Tests.Short),
                new HashFunctionWithTests(new BLAKE3(), BLAKE3Tests.Short),
            };
        }

        static List<HashFunctionWithTests> ToRunLong()
        {
            return new List<HashFunctionWithTests>
            {
                new HashFunctionWithTests(new JH_224(), JHTests.Long224),
                new HashFunctionWithTests(new JH_256(), JHTests.Long256),
                new HashFunctionWithTests(new JH_384(), JHTests.Long384),
                new HashFunctionWithTests(new JH_512(), JHTests.Long512),
                new HashFunctionWithTests(new Skein_VAR(Skein.InternalStateSize.Bits_512, 224), Skein_Tests.Long512_224),
            };
        }

        class TaskItem
        {
            public Func<List<TestResult>> FuncToRun;
            public Action<int> CompletedCallback;
        }

        class HashFunctionWithTests
        {
            public HashFunction HashFunction;
            public List<HashFunctionTest> Tests;

            public HashFunctionWithTests(HashFunction hf, List<HashFunctionTest> test)
            {
                HashFunction = hf;
                Tests = test;
            }
        }
    }
}
