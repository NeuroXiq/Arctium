using System;

namespace Arctium.Cryptography.ASN1.Standards.X509.Types
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
            switch (NameType)
            {
                case GeneralNameType.DNSName:
                    if (typeof(T) != typeof(string))
                        throw new ArgumentException($"For current NameType ({NameType}) valid convertion type is {typeof(string).Name}");
                    else break;
                default: throw new NotSupportedException("Current inner value are not supported for decoding");
            }



            // :)
            return (T)innerValue;
        }

        public override string ToString()
        {
            return innerValue.ToString();
        }
    }
}
