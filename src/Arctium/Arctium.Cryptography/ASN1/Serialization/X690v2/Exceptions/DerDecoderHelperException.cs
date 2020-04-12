using System;
using System.Collections.Generic;
using System.Text;

namespace Arctium.Cryptography.ASN1.Serialization.X690v2.Exceptions
{
    public class DerDecoderHelperException : Exception
    {
        public DerDecoderHelperException(string message) : base (message)
        {
        }
    }
}
