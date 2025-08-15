using System.Numerics;

namespace Arctium.Shared
{
    /// <summary>
    /// Simple math
    /// </summary>
    public class SMath
    {
        public static long DivideAndCeilUp(long number, long divider)
        {
            long t = number / divider;

            if (t * divider < number)
            {
                return t + 1;
            }

            return t;
        }
    }
}
