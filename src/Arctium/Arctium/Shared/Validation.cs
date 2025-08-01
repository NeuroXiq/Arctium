﻿using Arctium.Shared.Exceptions;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace Arctium.Shared
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

        public static void NotNegative(long value, string argName, string addtionalInfo = null)
        {
            if (value >= 0) return;

            string msg = "Invalid argument: '{0}'. Value cannot be null. Current value: '{1}'";
            msg = string.Format(msg, argName, value);

            if (addtionalInfo != null) msg = string.Format("{0}. {1}", msg, addtionalInfo);

            throw new ArgumentException(msg, argName);
        }

        public static void ThrowInternal(bool shouldThrow) { if (shouldThrow) throw new ArctiumExceptionInternal(); }

        public static void ThrowInternal(string message) => throw new ArctiumExceptionInternal(message);


        public static void IsInS<TType>(TType currentValue, string argName, params TType[] validValues) where TType : struct
        {
            IsInS(currentValue, validValues, argName, null);
        }

        public static void IsInS<TType>(TType currentValue, TType[] validValues, string argName, string additionalInfo = null) where TType: struct
        {
            foreach (var valid in validValues)
            {
                if (valid.Equals(currentValue)) return;
            }



            string msg = string.Format("Invalid argument: {0}. Value is not in possible ranges of values for this argument", argName);

            if (additionalInfo != null) msg = $"{msg}. Additional info: {additionalInfo}";

            throw new ArgumentException(msg, argName);
        }

        public static void EnumValueDefined<T>(T[] values, string argName, string additionalInfo = null) where T : struct, Enum
        {
            foreach (var val in values) EnumValueDefined(val, argName, additionalInfo);
        }

        public static void NumberInRange(int value, int minValue, int maxValue, string argName, string additionalInfo = null)
        {
            if (value >= minValue && value <= maxValue) return;

            string msg = string.Format("'{0}' value is not in valid range. Valid range: {1}-{2} but current {3}", argName, minValue, maxValue, value);
            if (additionalInfo != null) msg = string.Format("{0}. Additional info: {1}", msg, additionalInfo);

            throw new ArgumentException(msg, argName);
        }

        public static void EnumValueDefined<T>(T v, string argName, string additionalInfo = null) where T: struct, Enum
        {
            if (Enum.IsDefined<T>(v)) return;

            string msg = string.Format("Argument '{0}' invalid. Enum value not defined: {1}", argName, v.ToString());

            if (!string.IsNullOrEmpty(additionalInfo)) msg = string.Format("{0}. {1}", additionalInfo);

            throw new ArgumentException(msg, argName);
        }

        public static void EnumEqualTo<TEnum>(TEnum currentValue, TEnum expectedValue, string argName, string additionalInfo = null) where TEnum: struct
        {
            if (currentValue.Equals(expectedValue)) return;

            additionalInfo = additionalInfo == null ? String.Empty : additionalInfo;

            string msg = string.Format("Invalid argument: {0}. Expected value: {1} current value: {2}. Additional info: {3}",
                argName,
                expectedValue.ToString(),
                currentValue.ToString(),
                additionalInfo);

            throw new ArgumentException(msg);
        }

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

        public static void Argument(bool shouldThrow, string parameterName, string additinalInfo = null)
        {
            if (!shouldThrow) return;

            additinalInfo = additinalInfo ?? String.Empty;

            throw new ArgumentException($"Invalid parameter: {parameterName}. Additional info: {additinalInfo}");
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

        public static void InvalidOperation(bool shouldThrow, string v)
        {
            v = v ?? "";
            throw new InvalidOperationException("Operation is invalid: Additional info: " + v);
        }

        public static void InvalidOperation(string v) => InvalidOperation(true, v);

        public static void LengthMax(long currentLength, long maxLength, string argName)
        {
            if (currentLength > maxLength) ThrowArctium($"{argName} cannot exceed {maxLength}. Current value: {currentLength}");
        }

        static void ThrowArctium(string msg) => throw new ArctiumException(msg);

        public static void NotSupported(bool notsupportedm, string additionalMessage)
        {
            if (!notsupportedm) return;
            NotSupported(additionalMessage);
        }

        public static void NotSupported(string additinalMessage = null)
        {
            var assembly = System.Reflection.Assembly.GetExecutingAssembly();
            var version = assembly.GetName().Version.ToString();
            var name = assembly.FullName;
            var date = DateTime.Now;

            var arctiumVersion = typeof(Validation).Assembly;

            string msg = "This feature is currently not supported by Arctium implementation. (current date: ''{0}'' version: ''{1}'', assembly.name: ''{2}'' )";
            msg = string.Format(msg, date, version ?? "", name ?? "");

            if (additinalMessage != null)
            {
                msg = string.Format("{0}. {1}", additinalMessage, msg);
            }

            throw new NotSupportedException(msg);
        }

        public static void NotEmpty<T>(IEnumerable<T> enumerable, string argName, string additinalInfo = null)
        {
            NotNull(enumerable, argName, additinalInfo);

            if (enumerable.Any()) return;

            string msg = string.Format("Value cannot be empty list. Value: '{0}'", argName);

            if (additinalInfo != null) msg = string.Format("{0}. Additional info: {1}", msg, additinalInfo);

            throw new ArgumentException(msg, argName);
        }

        public static void NotNull(object referenceTypeToCheckIfNull, string argName, string additionalInfo = null)
        {
            if (referenceTypeToCheckIfNull != null) return;

            string msg = "Argument: '{0}' is null";

            if (additionalInfo != null) string.Format("{0}. Additional info: {1}", msg, additionalInfo);

            throw new ArgumentNullException(argName, msg);
        }
    }
}
