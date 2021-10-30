using System;

namespace Arctium.Tests.Core
{
    public class TestResult
    {
        public string Name;
        public bool Success;
        public Exception Exception;
        public Test Test;

        public TestResult()
        {
            
        }

        public TestResult(Test test, bool issuccess)
        {
            Test = test;
            Success = issuccess;
        }

        public TestResult(string name, bool success)
        {
            Name = name;
            Success = success;
        }

        public TestResult(Test t, Exception e, bool success)
        {
            Exception = e;
            Success = success;
            Test = t;
        }

        public TestResult(string testName, Exception e, bool success)
        {
            Name = testName;
            Exception = e;
            Success = success;
        }
    }
}
