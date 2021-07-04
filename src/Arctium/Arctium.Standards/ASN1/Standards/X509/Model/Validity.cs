using System;
using System.Collections.Generic;
using System.Text;

namespace Arctium.Standards.ASN1.Standards.X509.Model
{
    public struct Validity
    {
        public DateTime NotBefore;
        public DateTime NotAfter;

        public Validity(DateTime notBefore, DateTime notAfter)
        {
            NotBefore = notBefore;
            NotAfter = notAfter;
        }
    }
}
