using Arctium.Cryptography.ASN1.Exceptions;
using Arctium.Cryptography.ASN1.ObjectSyntax.Types;

namespace Arctium.Cryptography.ASN1.ObjectSyntax.Exceptions
{
    /// <summary>
    /// Exception is thrown when invalid assignment to a strict type occur
    /// </summary>
    public class InvalidStrictTypeException : Asn1Exception
    {
        /// <summary>
        /// Name of the expected type by <see cref="CurrentStrictType"/>
        /// </summary>
        public string ExpectedType { get; set; }

        /// <summary>
        /// Type (value) which was assigned to strict type
        /// </summary>
        public string AssignType { get; set; }

        /// <summary>
        /// Strict type throwing exception
        /// </summary>
        public string CurrentStrictType { get; set; }

        /// <summary>
        /// Creates a new instance of the <see cref="InvalidStrictTypeException"/>
        /// </summary>
        /// <param name="message">Exception message</param>
        /// <param name="currentStrictType">Strict type throwing this exception</param>
        /// <param name="expectedType">Type which was expected by <see cref="IAsn1StrictType{T}"/></param>
        /// <param name="assignType">Current type which was mistakenly to <paramref name="currentStrictType"/></param>
        public InvalidStrictTypeException(string message, string currentStrictType = "", string expectedType = "", string assignType = "") : base(message)
        {
            ExpectedType = expectedType;
            AssignType = assignType;
            CurrentStrictType = currentStrictType;
        }


        /// <summary>
        /// Helper method, creates new instance of this exception
        /// </summary>
        /// <typeparam name="TStrict">Throwing exception type</typeparam>
        /// <typeparam name="TExpected">Expected type to assign</typeparam>
        /// <param name="assign">Current assign value </param>
        /// <returns></returns>
        public static InvalidStrictTypeException Create<TStrict,TExpected>(object assign)
        {
            return new InvalidStrictTypeException("Invalid assignment value for strict type definition",
                typeof(TStrict).Name,
                typeof(TExpected).Name,
                assign == null ? "null" : assign.GetType().Name);
        }
    }
}