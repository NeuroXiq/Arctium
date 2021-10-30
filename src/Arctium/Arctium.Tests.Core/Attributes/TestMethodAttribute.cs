using System;
using System.Collections.Generic;
using System.Text;

namespace Arctium.Tests.Core.Attributes
{
    public class TestMethodAttribute : Attribute
    {
        public int ExpectedDurationInSeconds { get; set; }

        public TestMethodAttribute(int expectedDurationInSeconds = -1)
        {
            ExpectedDurationInSeconds = expectedDurationInSeconds;
        }
    }
}
