using Arctium.Shared.Exceptions;
using System;

namespace Arctium.Cryptography.HashFunctions.Hashes.Exceptions
{
    /// <summary>
    /// Exception is thrown when state of the hash function is invalid. This is an internal exception
    /// that indicating implementation pitfails and must not be thrown by public code
    /// </summary>
    class InvalidHashStateInternalException : ArctiumExceptionInternal
    {
        public InvalidHashStateInternalException(string message, string description, object throwingClassInstance) : base(message, description, throwingClassInstance)
        {
        }
    }
}
