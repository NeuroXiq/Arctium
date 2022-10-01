using Arctium.Shared.Exceptions;
using System;

namespace Arctium.Shared.Other
{
    public static class Validation
    {
        public static void ThrowInternal(bool shouldThrow, string msg) { if (shouldThrow) throw new ArctiumExceptionInternal(msg); }

        public static void ThrowInternal(bool shouldThrow) { if (shouldThrow) throw new ArctiumExceptionInternal(); }

        public static void ThrowInternal(string message) => throw new ArctiumExceptionInternal(message);

        public static void Length(byte[] bytes, long expectedLength, string argName, string additionalInfo = null)
        {
            if (bytes == null) throw new ArgumentNullException($"{argName} is null");
            if (bytes.Length != expectedLength)
            {
                string msg = $"{argName} length is invalid. Expected length: {expectedLength}";
                
                if (additionalInfo != null) msg += ". " + additionalInfo;
                
                ThrowArctium(msg);
            }
        }

        public static void Length(long currentLength, long expectedLength, string argName, string additionalInfo = null)
        {
            if (currentLength != expectedLength)
            {
                string msg = $"Invalid value of {argName}. Expected: '{expectedLength}' but current: '{currentLength}'";
                
                if (additionalInfo != null) msg += ". " + additionalInfo;

                ThrowArctium(msg);
            }
        }

        public static void LengthMax(long currentLength, long maxLength, string argName)
        {
            if (currentLength > maxLength) ThrowArctium($"{argName} cannot exceed {maxLength}. Current value: {currentLength}");
        }

        static void ThrowArctium(string msg) => throw new ArctiumException(msg);
    }
}
