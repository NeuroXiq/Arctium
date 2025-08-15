using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNSImpl.Model
{
    public class Message
    {
        // header fields

        public ushort Id;
        public bool QR;
        public byte Opcode;
        public bool AA;
        public bool TC;
        public bool RD;
        public bool RA;
        public const byte Z = 0;

        /// <summary>
        /// Response code
        /// </summary>
        public ResponseCode RCode;

        /// <summary>
        /// number of entries in the question section
        /// </summary>
        public ushort QDCount;


        /// <summary>
        /// number of resource records in the answer section
        /// </summary>
        public ushort ANCount;

        /// <summary>
        /// number of name server resource records in the authority records section
        /// </summary>
        public ushort NSCount;

        /// <summary>
        /// number of resource records in the additional records section
        /// </summary>
        public ushort ARCount;

        public Question[] Question;

        public ResourceRecord[] Answer;

        public ResourceRecord[] Authority;

        public ResourceRecord[] Additional;
    }
}
