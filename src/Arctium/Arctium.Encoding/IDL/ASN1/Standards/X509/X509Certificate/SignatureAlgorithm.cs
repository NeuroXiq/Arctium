using Arctium.DllGlobalShared.Constants;
using System;
using System.Collections.Generic;
using System.Text;

namespace Arctium.Encoding.IDL.ASN1.Standards.X509.X509Certificate
{
    public struct SignatureAlgorithm
    {
        public Algorithm Hash { get; private set; }
        public Algorithm Crypto { get; private set; }

        public SignatureAlgorithm(Algorithm hash, Algorithm crypto)
        {
            Hash = hash;
            Crypto = crypto;
        }
    }
}
