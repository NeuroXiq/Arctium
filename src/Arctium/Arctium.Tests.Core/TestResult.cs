using System;

namespace Arctium.Tests.Core
{
    public class TestResult
    {
        public string Name;
        public bool Success;
        public Exception Exception;

        public TestResult()
        { }

        public TestResult(string name, bool success)
        {
            Name = name;
            Success = success;
        }

        public TestResult(Exception e)
        {
            Exception = e;
        }
    }
}
