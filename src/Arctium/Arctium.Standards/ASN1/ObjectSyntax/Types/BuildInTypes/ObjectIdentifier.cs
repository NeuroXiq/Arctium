using Arctium.Shared.Helpers.Binary;
using System;

namespace Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes
{
    /// <summary>
    /// Represents Object Identifier value as an array of byte arrays where each of the subarray is a subidentifier value.
    /// </summary>
    public struct ObjectIdentifier
    {
        public byte[][] Subidentifiers { get; private set; }

        public ObjectIdentifier(byte[][] subidentifiers)
        {
            if (subidentifiers == null) throw new ArgumentNullException(nameof(subidentifiers));

            Subidentifiers = subidentifiers;
        }

        public ObjectIdentifier(params ulong[] oidValues)
        {
            if (oidValues == null) throw new ArgumentNullException(nameof(oidValues));
            if (oidValues.Length < 1) throw new ArgumentException("values cannot be empty");

            byte[][] subIds = new byte[oidValues.Length - 1][];

            var specialFistIdentifier =  (oidValues[0] * 40) + oidValues[1];
            subIds[0] = BinConverter.GetBytesTrimToLastLE(specialFistIdentifier);

            for (int i = 2; i < oidValues.Length; i++)
            {
                subIds[i - 1] = BinConverter.GetBytesTrimToLastLE(oidValues[i]);
            }

            Subidentifiers = subIds;
        }

        public override bool Equals(object obj)
        {
            if (obj == null) return false;
            if (!(obj is ObjectIdentifier)) return false;

            ObjectIdentifier oidObj = (ObjectIdentifier)obj;
            if (oidObj.Subidentifiers.Length != this.Subidentifiers.Length) return false;

            // Compare every byte in all subidentifiers
            for (int i = 0; i < this.Subidentifiers.Length; i++)
            {
                byte[] thisSubid = this.Subidentifiers[i];
                byte[] objSubid = oidObj.Subidentifiers[i];

                if (thisSubid.Length != objSubid.Length) return false;
                for (int j = 0; j < thisSubid.Length; j++)
                {
                    if (thisSubid[j] != objSubid[j]) return false;
                }
            }

            return true;
        }

        public override int GetHashCode()
        {
            int result = 0;
            int shift = 0;
            var s = Subidentifiers;

            for (int i = 0; i < s.Length; i++)
            {
                var ss = s[i];
                for (int j = 0; j < ss.Length; j++)
                {
                    result += (ss[j] << shift);
                    shift += 8;
                    shift %= 32;
                }
            }

            return result;
        }

        /// <summary>
        /// Converts OID numbers to 'dot notation' string
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            ulong[] numbers = ToNumbers();

            ulong secondComponent = numbers[0] % 40;
            ulong firstComponent = (numbers[0]- secondComponent) / 40;

            string result = $"{firstComponent}.{secondComponent}";

            for (int i = 1; i < numbers.Length; i++)
            {
                result += $".{numbers[i].ToString()}";
            }

            return result;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException">If OID subidentifier cannot be converted to ulong value (exceeds 8-byte structure)</exception>
        public ulong[] ToNumbers()
        {
            ulong[] numValues = new ulong[Subidentifiers.Length];

            try
            {
                for (int i = 0; i < Subidentifiers.Length; i++)
                {
                    numValues[i] = BinConverter.ToULongLE(Subidentifiers[i], 0, Subidentifiers[i].Length);
                }
            }
            catch (ArgumentException e)
            {
                throw new InvalidOperationException("Subidentifier of current OID object cannot be converter to unsigned integer");
            }

            return numValues;
        }
    }
}
