using System;

namespace Arctium.Cryptography.ASN1.Standards.X509.X509Cert
{
    public class X509Algorithm<T> where T: Enum
    {
        public T AlgorithmType { get; private set; }
        public IAlgorithmParms<T> Parameters { get; private set; }
        public IAlgorithmValue<T> Value { get; private set; }

        internal X509Algorithm(T type, IAlgorithmParms<T> parms, IAlgorithmValue<T> value)
        {
            AlgorithmType = type;
            Parameters = parms;
            Value = value;
        }
    }
}
