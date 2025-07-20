namespace Arctium.Standards.ASN1.Serialization
{
    public enum Asn1EncodingRule
    {
        /// <summary>
        /// Basic Encoding Rules
        /// </summary>
        BER,
        /// <summary>
        /// Distinguished Encoding Rules
        /// </summary>
        DER,
        /// <summary>
        /// Canonical Encoding Rules
        /// </summary>
        CER,
        /// <summary>
        /// Packed Encoding Rules
        /// </summary>
        PER,
        /// <summary>
        /// Unaligned PER
        /// </summary>
        UPER,
        /// <summary>
        /// Canonical PER
        /// </summary>
        CPER,
        /// <summary>
        /// Canonical unaligned
        /// </summary>
        CUPER,
        /// <summary>
        /// Encoding Control Notation
        /// </summary>
        ECN,
        /// <summary>
        /// XML Encoding Rules
        /// </summary>
        XER,
        /// <summary>
        /// Canonical XML Encoding Rules
        /// </summary>
        CXER,
        /// <summary>
        ///Extended XML Encoding Rules
        /// </summary>
        EXER,
        /// <summary>
        /// Octet Encoding Rules
        /// </summary>
        OER,
        /// <summary>
        /// Canonical Octet Encoding Rules
        /// </summary>
        COER,
        /// <summary>
        /// JSON Encoding Rules
        /// </summary>
        JER,
        /// <summary>
        /// Generic String Encoding Rules
        /// </summary>
        GSER
    }
}
