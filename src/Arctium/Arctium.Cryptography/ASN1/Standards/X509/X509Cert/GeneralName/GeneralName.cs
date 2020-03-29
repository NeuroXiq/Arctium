using System;

namespace Arctium.Cryptography.ASN1.Standards.X509.X509Cert
{
    public class GeneralName
    {
        public readonly GeneralNameType NameType;

        internal GeneralName(GeneralNameType nameType, object innerValue)
        {
            NameType = nameType;
            this.innerValue = innerValue;
        }

        // TODO X509 define strict types
        public object innerValue;


        public T Get<T>()
        {
            ThrowIfInvalidConversion<T>();
            return (T)innerValue;
        }

        private void ThrowIfInvalidConversion<T>()
        {
            Type validType;
            Type curType = typeof(T);

            switch (NameType)
            {
                case GeneralNameType.DNSName: validType = typeof(string);
                    break;
                default: throw new NotSupportedException("Current inner value are not supported for decoding. <INTERNAL_EXCEPTION>");
            }

            if(validType != curType)
                    throw new ArgumentException($"For current NameType ({NameType}) valid convertion type is {validType}");

        }

        public override string ToString()
        {
            return innerValue.ToString();
        }
    }
}
