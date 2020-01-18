namespace Arctium.Connection.Tls.Tls12.CryptoConfiguration.ECC
{
    class ECDomainParameters
    {
        public byte[] P;
        public byte[] A;
        public byte[] B;
        public byte[] Gx;
        public byte[] Gy;
        public byte[] N;
        public byte[] H;

        public ECDomainParameters(byte[] p, byte[] a, byte[] b, byte[] gx, byte[] gy, byte[] n, byte[] h)
        {
            P = p;
            A = a;
            B = b;
            Gx = gx;
            Gy = gy;
            N = n;
            H = h;
        }
    }
}
