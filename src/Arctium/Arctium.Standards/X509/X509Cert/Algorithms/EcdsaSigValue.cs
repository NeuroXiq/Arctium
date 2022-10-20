using Arctium.Standards.ArctiumLibShared;

namespace Arctium.Standards.X509.X509Cert.Algorithms
{
    /// <summary>
    /// Represents decoded Ecdsa-Sig-Value ASN1 structure.
    /// R, S are integers represented as byte arrays signed big endian byte arrays
    /// </summary>
    public class EcdsaSigValue
    {
        public byte[] R;
        public byte[] S;

        public EcdsaSigValue(IArctiumConvertable<ArctiumLibShared.ECSignature> convertable)
        {
            var converted = convertable.Convert();

            R = converted.R.ToByteArray(true, true);
            S = converted.R.ToByteArray(true, true);
        }

        public EcdsaSigValue(byte[] r, byte[] s)
        {
            R = r;
            S = s;
        }
    }
}
