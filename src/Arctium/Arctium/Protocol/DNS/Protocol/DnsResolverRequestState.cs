using Arctium.Protocol.DNS.Model;

namespace Arctium.Protocol.DNS.Protocol
{
    /// <summary>
    /// request state as described in rfc 1034, page 33
    /// </summary>
    internal class DnsResolverRequestState
    {
        public string SName { get; set; }
        public QType SType { get; set; }
        public QClass SClass { get; set; }
        public object SList { get; set; }
        public object SBelt { get; set; }
        public object Cache { get; set; }

        public DnsResolverRequestState(string sname, QClass sclass, QType stype)
        {
            SName = sname;
            SType = stype;
            SClass = sclass;
        }
    }
}
