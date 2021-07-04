using System;
namespace Arctium.Standards.ASN1.Shared.Exceptions
{
    public class ASN1CastException: Exception
    {
        public Type Expected { get; private set; }
        public Type Current { get; private set; }
        public string ClassName { get; private set; }
        public string AdditionalMessage { get; private set; }

        public ASN1CastException(Type expected, Type current, 
            string message = "", string className = "", string additionalMessage = "") : base(message)
        {
            Expected = expected;
            Current = current;
            ClassName = ClassName;
            AdditionalMessage = additionalMessage;
        }

        /// <summary>
        /// Builds <see cref="ASN1CastException"/> exception with formatted messages
        /// </summary>
        /// <typeparam name="E">Expected type which shall be used in a cast</typeparam>
        /// <typeparam name="C">Current type used in a cast</typeparam>
        /// <typeparam name="T">Class where this exception is throw</typeparam>
        /// <param name="additionalMessage">Additional informations</param>
        public static ASN1CastException Build<E, C, T>(string additionalMessage = "")
        {
            Type expected = typeof(E);
            Type current = typeof(C);
            string classThrowingException = typeof(T).Name;

            string message =
                $"Invalid castring to X509Type in {classThrowingException}" +
                $"Expected type: '{expected.Name}' but trying to cast to: '{current.Name}'";

            if (!string.IsNullOrWhiteSpace(additionalMessage)) message += additionalMessage;

            return new ASN1CastException(expected, current,
                message, classThrowingException, additionalMessage);
        }

        public static ASN1CastException Build<C, T>(Type expectedType, string additionalMessage = "")
        {
            Type expected = expectedType;
            Type current = typeof(C);
            string classThrowingException = typeof(T).Name;

            string message =
                $"Invalid castring to X509Type in {classThrowingException}" +
                $"Expected type: '{expected.Name}' but trying to cast to: '{current.Name}'";

            if (!string.IsNullOrWhiteSpace(additionalMessage)) message += additionalMessage;

            return new ASN1CastException(expected, current,
                message, classThrowingException, additionalMessage);
        }

        public static void ThrowIfInvalidCast<C, T>(Type expected)
        {
            if (typeof(C) != expected)
            {
                throw Build<C, T>(expected);
            }
        }
    }
}
