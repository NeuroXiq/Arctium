using System;
using System.Collections.Generic;
using System.Text;

namespace Arctium.Cryptography.ASN1.Standards.X509.X509Cert.Extensions.GeneralNameDef
{
    public enum GeneralNameType
    {
        OtherName,
        Rfc822Name,
        DNSName,
        X400Address,
        DirectoryName,
        EdiPartyName,
        UniformResourceIdentifier,
        IPAddress,
        RegisteredID
    }
}
