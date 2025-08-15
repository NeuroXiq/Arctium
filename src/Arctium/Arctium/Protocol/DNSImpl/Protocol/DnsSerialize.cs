using Arctium.Protocol.DNSImpl.Model;
using Arctium.Shared;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNSImpl.Protocol
{
    public class DnsSerialize
    {
        public DnsSerialize()
        { }

        // encoding

        public void Encode(Message message, ByteBuffer buffer)
        {
            
        }


        // decoding

        public Message Decode(byte[] buffer, int offset, int length)
        {
            throw new Exception();
        }
    }
}
