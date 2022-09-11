using System;

namespace Arctium.Shared.Exceptions
{
    public class ArctiumExceptionInternal : Exception
    {
        const string Message = "INTERNAL: This exception should never happen." +
            " This exception is throw because of incorrect implementation, behaviour, unexpected state of the algorithm. ";

        public string Description { get; private set; }

        public object ThrowClassInstance { get; private set; }

        public ArctiumExceptionInternal() : base(Message) { }

        public ArctiumExceptionInternal(string message, string description, object throwingClassInstance) : base(message + Message)
        {
            Description = description;
            ThrowClassInstance = throwingClassInstance;
        }
    }
}
