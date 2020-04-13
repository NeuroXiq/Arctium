using Arctium.Cryptography.ASN1.ObjectSyntax.Types;
using Arctium.Cryptography.ASN1.Serialization.X690v2.Exceptions;
using System;

namespace Arctium.Cryptography.ASN1.Serialization.X690v2.DER
{
    public static class DerDecoderHelper
    {
        public static DerDecoded[] SequenceCSAllOptional(DerDecoded decoded, int max, out bool[] itemsExists)
        {
            if (decoded.ConstructedCount > max)
            {
                throw new DerDecoderHelperException("Invalid length of optionlan parameters in constructed type. " +
                    "length exceed maximum number");
            }

            DerDecoded[] values = new DerDecoded[decoded.ConstructedCount];
            bool[] exists = new bool[values.Length];

            long prev = -1;

            foreach (var item in decoded)
            {
                long current = item.Tag.Number;

                if (current < prev)
                    throw new DerDecoderHelperException("Invalid order of optional tags in a CHOICE sequence");
                if (item.Tag.Class != TagClass.ContextSpecific)
                    throw new DerDecoderHelperException("Current item tag class is not a Context specific ");


                exists[current] = true;
                values[current] = item;
            }

            itemsExists = exists;
            return values;
        }

        /// <summary>
        /// Returns all bytes (including tag) representing gived decoding result
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="decoded"></param>
        /// <returns></returns>
        public static byte[] GetBytes(byte[] buffer, DerDecoded decoded)
        {
            byte[] copy = new byte[decoded.Length];

            Array.Copy(buffer, decoded.Offset, copy, 0, decoded.Length);

            return copy;
        }
    }
}
