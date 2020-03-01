using System;
using System.Reflection;

namespace Arctium.DllGlobalShared.Exceptions
{
    public class ArctiumExceptionInternal : Exception
    {

        public string Description { get; private set; }

        public object ThrowClassInstance { get; private set; }

        public ArctiumExceptionInternal(string message, string description, object throwingClassInstance) : base(message)
        {
            Description = description;
            ThrowClassInstance = throwingClassInstance;
        }
    }
}
