using Arctium.Standards.ASN1.Shared.Exceptions;
using Arctium.Standards.ASN1.Standards.X509.Exceptions;
using System;

namespace Arctium.Standards.X509.X509Cert.Extensions
{
    public class PolicyQualifierInfo
    {
        // CONSIDER this qualifier === OID and supports only RFC-defined oids. 
        // Support can be for not standrrd (no-internet-purpose) values ?

        public PolicyQualifierId PolicyQualifierId { get; private set; }

        // represents not typed value of qualifier
        // can be represented as 'string' or 'UserNotice' objects
        // depends on PolicyQualifierId enum field
        object genericInnerQualifier;

        public PolicyQualifierInfo(UserNotice userNotice)
        {
            this.PolicyQualifierId = PolicyQualifierId.UserNotice;
            genericInnerQualifier = userNotice;
        }

        public PolicyQualifierInfo(string cpsUri)
        {
            this.PolicyQualifierId = PolicyQualifierId.CPS;
            genericInnerQualifier = cpsUri;
        }

        public T GetQualifier<T>()
        {
            ThrowIfInvalidCast<T>();
            return (T)genericInnerQualifier;
        }

        private void ThrowIfInvalidCast<T>()
        {
            Type expected;
            Type current = typeof(T);

            switch (PolicyQualifierId)
            {
                case PolicyQualifierId.CPS: expected = typeof(string);
                    break;
                case PolicyQualifierId.UserNotice: expected = typeof(UserNotice);
                    break;
                default: // for safety reasons - internal exception, this must not never throw
                    throw new X509InternalException("PolicyQualifier id not found in switch in enum.", this);
            }

            if (expected != current)
            {
                throw ASN1CastException.Build<string, T, PolicyQualifierInfo>();
            }
        }
    }
}
