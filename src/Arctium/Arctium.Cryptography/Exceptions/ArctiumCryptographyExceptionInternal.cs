using Arctium.DllGlobalShared.Exceptions;
using System;

namespace Arctium.Cryptography.Exceptions
{
    internal class ArctiumCryptographyExceptionInternal : ArctiumExceptionInternal
    {
        public ArctiumCryptographyExceptionInternal(string message, string description, object throwingClassInstance) : base(message, description, throwingClassInstance)
        {
        }
    }
}
