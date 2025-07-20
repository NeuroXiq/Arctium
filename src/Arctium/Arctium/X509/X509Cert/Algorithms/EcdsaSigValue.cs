using Arctium.Standards.ArctiumLibShared;

namespace Arctium.Standards.X509.X509Cert.Algorithms
{
    /// <summary>
    /// Represents decoded Ecdsa-Sig-Value ASN1 structure.
    /// R, S are integers represented as byte arrays signed big endian byte arrays. Uses unsigned encoding
    /// (BigInteger is converted to byte array using unsigned encoding, means if first bit is 1 then zero-byte is perpended)
    /// </summary>
    public class EcdsaSigValue : IArctiumConvertable<Arctium.Cryptography.Ciphers.EllipticCurves.ECSignature>
    {
        public byte[] R;
        public byte[] S;

        public EcdsaSigValue(IArctiumConvertable<ArctiumLibShared.ECSignature> convertable)
        {
            var converted = convertable.Convert();

            R = converted.R.ToByteArray(false, true);
            S = converted.S.ToByteArray(false, true);
        }

        public EcdsaSigValue(byte[] r, byte[] s)
        {
            R = r;
            S = s;
        }

        public Cryptography.Ciphers.EllipticCurves.ECSignature Convert()
        {
            return new Cryptography.Ciphers.EllipticCurves.ECSignature(R, S);
        }
    }
}
