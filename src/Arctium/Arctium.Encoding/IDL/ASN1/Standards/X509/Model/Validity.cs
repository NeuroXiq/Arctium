using System;

namespace Arctium.Encoding.IDL.ASN1.Standards.X509.Types.Model
{
    public class Validity
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
