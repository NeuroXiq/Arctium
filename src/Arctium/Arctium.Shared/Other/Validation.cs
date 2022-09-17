using Arctium.Shared.Exceptions;
using System;

namespace Arctium.Shared.Other
{
    public static class Validation
    {
        public static void ThrowInternal(string message) => throw new ArctiumExceptionInternal(message);

        public static void Length(byte[] key, int expectedLength, string argName)
        {
            if (key == null) throw new ArgumentNullException($"{argName} is null");
            if (key.Length != expectedLength) ThrowArctium($"{argName} length is invalid. Expected key length: {expectedLength}");
        }

        public static void Length(long currentLength, long expectedLength, string argName)
        {
            if (currentLength != expectedLength) ThrowArctium($"Invalid value of {argName}. Expected: '{expectedLength}' but current: '{currentLength}'");
        }

        public static void LengthMax(long currentLength, long maxLength, string argName)
        {
            if (currentLength > maxLength) ThrowArctium($"{argName} cannot exceed {maxLength}. Current value: {currentLength}");
        }

        static void ThrowArctium(string msg) => throw new ArctiumException(msg);
    }
}
