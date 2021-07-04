using System;

namespace Arctium.Standards.ASN1.Standards.X509.X509Cert.Extensions
{
    public class BasicConstraintsExtension : CertificateExtension
    {
        /// <summary>
        /// Indicates if certificate public key may be used to verify certificate signature.
        /// </summary>
        public bool CA { get; private set; }

        /// <summary>
        /// If <see cref="PathLenConstraintExists"/> is false, this value MUST be ignored (is null) <br/>
        /// 
        /// Indicates maximum number of intermediates in a certification path. This value is meaningfully if
        /// <see cref="CA"/> is asserted and if key usage extension asserts <see cref="KeyUsageExtension.KeyCertSign"/>
        /// </summary>
        public int PathLenConstraint { get; private set; }

        /// <summary>
        /// Indicates if <see cref="PathLenConstraint"/> are present
        /// in current extension. If value is true, <see cref="PathLenConstraint"/>
        /// extists in extension otherwise is not included. In second case, 
        /// <see cref="PathLenConstraint"/> must be ignored in processing of this
        /// extension.
        /// </summary>
        public bool PathLenConstraintExists { get; private set; }

        /// <summary>
        /// Creates instance where <see cref="PathLenConstraint"/> is not present.
        /// </summary>
        /// <param name="ca"></param>
        /// <param name="pathLenConstraint"></param>
        /// <param name="isCritical"></param>
        public BasicConstraintsExtension(bool ca, bool isCritical) : base(ExtensionType.BasicConstraints, isCritical)
        {
            PathLenConstraintExists = false;
            PathLenConstraint = -1;
            CA = ca;
        }

        /// <summary>
        /// Creates instance where <see cref="PathLenConstraint"/> is present.
        /// </summary>
        /// <param name="ca"></param>
        /// <param name="pathLenConstraint"></param>
        /// <param name="isCritical"></param>
        public BasicConstraintsExtension(bool ca, int pathLenConstraint, bool isCritical) : base(ExtensionType.BasicConstraints, isCritical)
        {
            if (pathLenConstraint < 0) throw new ArgumentException("pathLenConstraint cannot be a negative value");

            PathLenConstraintExists = true;
            PathLenConstraint = pathLenConstraint;
            CA = ca;
        }
    }
}
