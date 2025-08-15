using Arctium.Shared;

namespace Arctium.Standards.X509.X509Cert.Extensions
{
    public class KeyUsageExtension : CertificateExtension
    {
        public struct KeyUsageFlags
        {
            public bool DigitalSignature;
            public bool NonRepudiation;
            public bool KeyEncipherment;
            public bool DataEncipherment;
            public bool KeyAgreement;
            public bool KeyCertSign;
            public bool CRLSign;
            public bool EncipherOnly;
            public bool DecipherOnly;
        }

        public bool DigitalSignature { get { return flags.DigitalSignature; } }
        public bool NonRepudiation { get { return flags.NonRepudiation; } }
        public bool KeyEncipherment { get { return flags.KeyEncipherment; } }
        public bool DataEncipherment { get { return flags.DataEncipherment; } }
        public bool KeyAgreement { get { return flags.KeyAgreement; } }
        public bool KeyCertSign { get { return flags.KeyCertSign; } }
        public bool CRLSign { get { return flags.CRLSign; } }
        public bool EncipherOnly { get { return flags.EncipherOnly; } }
        public bool DecipherOnly { get { return flags.DecipherOnly; } }

        private KeyUsageFlags flags;

        public KeyUsageExtension(bool isCritical, KeyUsageFlags flags) : base(ExtensionType.KeyUsage, isCritical)
        {
            this.flags = flags;
        }   
    }
}
