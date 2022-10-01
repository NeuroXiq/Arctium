using Arctium.Shared.Exceptions;
using System;

namespace Arctium.Shared.Other
{
    public static class Validation
    {
        /// <summary>
        /// This exception must never happen
        /// Internal exception should be throw on invalid/unexpected errors and should never happen.
        /// Can be useful for debugging, asserting valid state, or other reasons.
        /// Must never be thrown if code works as expected but if this kind of error occur,
        /// should be interpretet as unexpected state of the code
        /// (invalid code implementation, this doesn't mean invalid configuration from outside.
        /// For invalid configurations other exceptions must be thrown.
        /// Any possible configuration of any class by library consumer must not be able to
        /// produce this exception, other exceptions should be thrown if needed.)
        /// that need to be fixed.
        /// If exception throws, then algorithm/code must be fixed because does not work as expected.
        /// </summary>
        public static void ThrowInternal() => ThrowInternal(true);

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
