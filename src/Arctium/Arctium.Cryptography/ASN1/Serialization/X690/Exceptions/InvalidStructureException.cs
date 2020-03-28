using System;

namespace Arctium.Cryptography.ASN1.Serialization.X690.Exceptions
{
    public class InvalidStructureException: Exception
    {
        public InvalidStructureException(string message) : base(message)
        {

        }
    }
}
