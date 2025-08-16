using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNSImpl.Model
{
    public class Message
    {
        public Header Header;

        public Question[] Question;

        public ResourceRecord[] Answer;

        public ResourceRecord[] Authority;

        public ResourceRecord[] Additional;
    }
}
