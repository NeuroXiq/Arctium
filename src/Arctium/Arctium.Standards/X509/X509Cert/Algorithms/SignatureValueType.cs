namespace Arctium.Standards.X509.X509Cert.Algorithms
{
    public enum SignatureValueType
    {
        /// <summary>
        /// Not defined in specification to have some special underlying structure (e.g. RSA signature is just a raw bytes).
        /// Contrary ECDSA has special underlying structure (two byte array R, S and need to decode it)
        /// </summary>
        NotDefined_RawBytes,

        EcdsaSigValue
    }
}
