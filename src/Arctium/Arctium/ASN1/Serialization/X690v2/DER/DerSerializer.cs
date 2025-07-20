using Arctium.Shared.Other;

namespace Arctium.Standards.ASN1.Serialization.X690v2.DER
{
    public class DerSerializer
    {
        public static int Emit(int tagclass,
            bool pc,
            int tagnumber,
            int contentslen,
            byte[] outputbuf,
            int endoffset)
        {
            int start = endoffset;

            if (contentslen > 255) Validation.NotSupported();

            if (contentslen <= 0x7F)
            {
                outputbuf[endoffset] = (byte)contentslen;
                endoffset--;
            }
            else
            {
                outputbuf[endoffset] = (byte)(contentslen & 0xFF);
                endoffset--;
                // outputbuf[endoffset] = (byte)(((contentslen >> 8) & 0xFF));
                //endoffset--;
                outputbuf[endoffset] = (byte)(0x80 | (1));
                endoffset--;
            }

            // len
            //for (int i = 0; i < 5; i++)
            //{
            //    byte v = (byte)((contentslen >> (7 * i)) & (0x7F));

            //    if (v == 0) break;

            //    if (i != 0) v |= 0x80;

            //    outputbuf[endoffset] = v;
            //    endoffset--;
            //}
            if (tagnumber > 31) Validation.NotSupported();

            byte id = 0;
            id |= (byte)(tagclass << 6);
            id |= (byte)((pc ? 1 : 0) << 5);
            id |= (byte)(tagnumber);

            outputbuf[endoffset] = id;
            endoffset -= 1;

            return start - endoffset;
        }
    }
}
