namespace Arctium.Standards.X509.X509Cert.Algorithms
{
    public class EcdsaSigValue
    {
        public byte[] R;
        public byte[] S;

        public EcdsaSigValue(byte[] r, byte[] s)
        {
            R = r;
            S = s;
        }
    }
}
