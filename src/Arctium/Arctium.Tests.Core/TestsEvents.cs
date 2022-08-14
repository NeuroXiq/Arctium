using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Tests.Core
{
    public class TestsEvents
    {
        public static void RaiseProgressEvent(string className, string testName, int progress)
        {
            Console.WriteLine($"-PROGRESS: {className} / {testName}: {progress}%");
        }
    }
}
