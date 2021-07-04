using System;

namespace Arctium.Standards.ASN1.Standards.X509.X509Cert.Extensions
{
    [Flags]
    public enum ReasonFlags : int
    {
        Unused = 1 << 0,
        KeyCompromise = 1 << 1,
        CACompromise = 1 << 2,
        AffiliationChanged =1 << 3,
        Superseded = (1 << 4),
        CessationOfOperation = (1 << 5),
        CertificateHold = (1 << 6),
        PrivilegeWithdrawn = (1 << 7),
        AACompromise =(1 << 8) 
    }
}
