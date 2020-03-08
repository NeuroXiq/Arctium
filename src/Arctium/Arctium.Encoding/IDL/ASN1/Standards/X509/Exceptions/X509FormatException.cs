using Arctium.DllGlobalShared.Exceptions;
using System;
using System.Collections.Generic;
using System.Text;

namespace Arctium.Encoding.IDL.ASN1.Standards.X509
{
    public class X509FormatException : ArctiumException
    {
        public object Metadata { get; private set; }
        public X509FormatException(string message, object metadata) : base(message)
        {
            Metadata = metadata;
        }
    }
}
