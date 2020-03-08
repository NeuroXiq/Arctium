using Arctium.Encoding.IDL.ASN1.Exceptions;
using System;
using System.Collections.Generic;

namespace Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types
{
    /// <summary>
    /// Helper class facilitates work with raw decoded types.
    /// </summary>
    public static class Asn1TaggedTypeHelper
    {
        /// <summary>
        /// If possible, converts generic <see cref="Asn1TaggedType"/> to more specific.
        /// Otherwise throws exception
        /// </summary>
        /// <typeparam name="T">Convertions result type</typeparam>
        /// <param name="type">Generic type to convert</param>
        /// <returns>Converted value</returns>
        /// <exception cref=""></exception>
        public static T AsSpecific<T>(Asn1TaggedType type) where T : class
        {
            var result = type as T;
            if (result == null) throw new Asn1InternalException("Invalid cast:"+(typeof(T).Name),"",typeof(Asn1TaggedTypeHelper));

            return result;
        }

        public static List<T> AsSpecificList<T>(List<Asn1TaggedType> sourceList) where T : class
        {
            return (List<T>)((IEnumerable<T>)sourceList);// as List<T>;
        }

        public static bool Is<T>(Asn1TaggedType type)
        {
            return (type is T);
        }

        public static bool Is(Asn1TaggedType type, Tag tag)
        {
            return type.Tag.Equals(tag);
        }

        /// <summary>
        /// Determines if a provided constructed type contains all types provided in <paramref name="types"/> parameter.<br/>
        /// Order and number of elements must match.<br/>
        /// This is a shallow comparison, means that the <paramref name="types"/> are a first childs of the container.<br/>
        /// Childs of childs are ignored.
        /// </summary>
        /// <param name="container"></param>
        /// <param name="types"></param>
        /// <returns>If some type was not found, first type that not appear in <paramref name="container"/> is returent (unexpected type)</returns>
        public static bool HaveOrderedExactShallow(Asn1TaggedType container, params Tag[] tags)
        {
            if (tags == null) throw new Asn1InternalException("'types' cannot be null", "", typeof(Asn1TaggedTypeHelper));

            // assumes that this returns list
            List<Asn1TaggedType> innerValues;
            try
            {
                innerValues = (List<Asn1TaggedType>)container.Value;
            }
            catch
            {
                throw new Asn1InternalException("Cannot check this constructor in Asn1TaggedTypeHelper",
                    "This constructor do not return List<T> of some object therefore types comparison is impossible",
                    "ASN1TaggedTypeHelper (STATIC)");
            }


            if (tags.Length == innerValues.Count)
            {
                for (int i = 0; i < tags.Length; i++)
                {
                    if (!tags[i].Equals(innerValues[i].Tag)) return false;
                }

                return true;
            }

            return false;
        }
    }
}
