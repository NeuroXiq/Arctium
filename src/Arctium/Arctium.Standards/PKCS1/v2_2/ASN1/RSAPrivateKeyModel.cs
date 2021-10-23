using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using System;
using System.Collections.Generic;
using System.Text;

namespace Arctium.Standards.PKCS1.v2_2.ASN1
{
    class RSAPrivateKeyModel
    {
        public Integer Version;
        public Integer Modulus;
        public Integer PublicExponent;
        public Integer PrivateExponent;
        public Integer Prime1;
        public Integer Prime2;
        public Integer Exponent1;
        public Integer Exponent2;
        public Integer Coefficient;
        public OtherPrimeInfoModel[] OtherPrimeInfos;
    }
}
