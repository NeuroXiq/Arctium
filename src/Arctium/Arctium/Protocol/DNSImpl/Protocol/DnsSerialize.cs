using Arctium.Protocol.DNS;
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

        public Message Decode(BytesSpan buffer)
        {
            Message result = new Message();
            Header header = Decode_Header(buffer, out int decodedLength);
            buffer.ShiftOffset(decodedLength);

            // todo: validate max no entries

            result.Question = new Question[header.QDCount];
            result.Answer = new ResourceRecord[header.ANCount];
            result.Authority = new ResourceRecord[header.NSCount];
            result.Additional = new ResourceRecord[header.ARCount];


            for (int i = 0; i < header.QDCount; i++)
            {
                result.Question[i] = Decode_Question(buffer, out decodedLength);
                buffer.ShiftOffset(decodedLength);
            }

            for (int i = 0; i < header.ANCount; i++)
            {

            }

            for (int i = 0; i < header.NSCount; i++)
            {

            }

            for (int i = 0; i < header.ARCount; i++)
            {

            }

            result.Header = header;

            return result;
        }

        private Question Decode_Question(BytesSpan buffer, out int decodedLength)
        {
            Question result = new Question();
            int i = 0;
            List<string> labels = new List<string>();

            while (buffer[i] > 0)
            {
                int labelLengt = buffer[i];

                if (labelLengt > 63) throw new DnsException(DnsProtocolError.InvalidLabelLength);
                if (i + buffer.Offset >= buffer.Length) throw new DnsException(DnsProtocolError.InvalidLabelLength);

                if (labelLengt > 0)
                    labels.Add(Encoding.ASCII.GetString(buffer.Buffer, buffer.GetIndex(i + 1), labelLengt));

                i += labelLengt + 1;
            }
            
            i += 1;

            result.QName = string.Join(".", labels.ToArray());
            result.QType = (QType)BinConverter.ToUShortBE(buffer.Buffer, buffer.GetIndex(i));
            result.QClass = (QClass)BinConverter.ToUShortBE(buffer.Buffer, buffer.GetIndex(i + 2));

            i += 4;

            decodedLength = i;
            return result;
        }

        private Header Decode_Header(BytesSpan buffer, out int decodedLength)
        {
            if (buffer.Length < 12) throw new DnsException("decode error: min header length < 12");

            Header header = new Header();
            header.Id = (ushort)(buffer[0] << 8 | buffer[1]);
            header.QR = (buffer[2] & 0x80) ==1;
            header.Opcode = (byte)((buffer[3] & 0x78) >> 3);
            header.AA = (buffer[2] & 0x04) == 1;
            header.TC = (buffer[2] & 0x02) == 1;
            header.RD = (buffer[2] & 0x01) == 1;
            header.RA = (buffer[3] & 0x80) == 1;

            if ((buffer[4] & 0x70) != 0) throw new DnsException("decode error, Z value in header is not zero");
            
            header.RCode = (ResponseCode)(buffer[3] & 0x0F);
            header.QDCount = BinConverter.ToUShortBE(buffer.Buffer, buffer.Offset + 4);
            header.ANCount = BinConverter.ToUShortBE(buffer.Buffer, buffer.Offset + 6);
            header.NSCount = BinConverter.ToUShortBE(buffer.Buffer, buffer.Offset + 8);
            header.ARCount = BinConverter.ToUShortBE(buffer.Buffer, buffer.Offset + 10);

            decodedLength = 12;

            return header;
        }
    }
}
