﻿namespace Arctium.Standards.X509.X509Cert.GenName
{
    public enum GeneralNameType
    {
        OtherName,
        Rfc822Name,
        DNSName,
        X400Address,

        /// <summary>
        /// X501 Name
        /// </summary>
        Name,
        EdiPartyName,
        UniformResourceIdentifier,
        IPAddress,
        RegisteredID
    }
}
