using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Tests.Core;
using System;
using System.Collections.Generic;
using System.Text;

namespace Arctium.Tests.Cryptography.HashFunctions
{
    static class ExecuteHashFunctionTests
    {
        public static List<TestResult> RunTests(HashFunction hash, List<HashFunctionTest> tests)
        {
            List<TestResult> results = new List<TestResult>();
            TestResult result = null;

            foreach (var test in tests)
            {
                if (test.UseInput == HashFunctionTest.InputToUse.InputBytes) result = RunBufferTest(hash, test);
                else result = RunStreamTest(hash, test);

                results.Add(result);
            }

            return results;
        }

        static TestResult RunStreamTest(HashFunction hash, HashFunctionTest test)
        {
            TestResult r = null;
            hash.HashBytes(test.Stream);

            try
            {
                hash.HashBytes(test.Stream);
                byte[] res = hash.HashFinal();
                
                r = new TestResult(test, MemOps.Memcmp(res, test.ExpectedResultHash));

                hash.Reset();
            }
            catch (Exception e)
            {
                r = new TestResult(test, e, false);
            }

            return r;
        }

        static TestResult RunBufferTest(HashFunction hash, HashFunctionTest test)
        {
            TestResult r;

            try
            {
                hash.HashBytes(test.InputBytes);
                byte[] result = hash.HashFinal();

                bool success = MemOps.Memcmp(result, test.ExpectedResultHash);

                r = new TestResult(test, success);

                hash.Reset();
            }
            catch (Exception e)
            {
                r = new TestResult(test, e, false);
            }

            return r;
        }
    }
}
