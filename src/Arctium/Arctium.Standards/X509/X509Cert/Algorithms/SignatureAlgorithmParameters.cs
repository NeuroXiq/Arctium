using Arctium.Standards.ASN1.Shared;
using System;

namespace Arctium.Standards.X509.X509Cert.Algorithms
{
    public class SignatureAlgorithmParameters : ChoiceObj<SignatureAlgorithmType>
    {
        protected override TypeDef[] ChoiceObjConfig => throw new NotImplementedException();

        public SignatureAlgorithmParameters() { throw new NotImplementedException(""); }
    }
}
