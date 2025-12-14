namespace Arctium.Protocol.DNS.Model
{
    public class RDataNS
    {
        /// <summary>
        /// a domain-name which specifies a host which should be authoritative
        /// for the specified class and domain
        /// </summary>
        public string NSDName;

        public RDataNS() { }
        
        public RDataNS(string nsdName) { NSDName = nsdName; }

        public override string ToString()
        {
            return NSDName;
        }
    }
}
