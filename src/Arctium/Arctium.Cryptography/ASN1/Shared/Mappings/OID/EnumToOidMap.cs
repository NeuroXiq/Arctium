using System;
using System.Collections.Generic;
using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Shared.Helpers.DataStructures;

namespace Arctium.Cryptography.ASN1.Shared.Mappings.OID
{
    // main purpose is to have a formatted exceptions

    /// <summary>
    /// Mappins from OID to Enum and reverse are so common that 
    /// this class provides repeatable steps to create these mappings. <br/>
    /// </summary>
    /// <typeparam name="T">Enumerated type</typeparam>
    /// 
    public class EnumToOidMap<T>
    {
        DoubleDictionary<T, ObjectIdentifier> map;

        public readonly string MappingName;

        public EnumToOidMap(string mappingFullName)
        {
            if (!typeof(T).IsEnum)
                throw new Exception("T value shall be an enumerated type");

            map = new DoubleDictionary<T, ObjectIdentifier>();
            MappingName = mappingFullName;
        }

        public ObjectIdentifier this[T key]
        {
            get
            {
                ThrowIfKeyNotFound(key);
                return map[key];
            }
            set
            {
                ThrowIfKeyExists(key);
                map[key] = value;
            }
        }

        public T this[ObjectIdentifier key]
        {
            get
            {
                ThrowIfKeyNotFound(key);
                return map[key];
            }
            set
            {
                ThrowIfKeyExists(key);
                map[key] = value;
            }
        }

        private void ThrowIfKeyExists(ObjectIdentifier key)
        {
            if (map.ContainsKey(key))
            {
                string message =
                    $"{MappingName}: " +
                    "Provided OID key is already present in mapping." +
                    $"Trying to assign OID key: {key.ToString()} but" +
                    $"current assigned Enum value is: {map[key].ToString()}";
                throw new ArgumentException(message);
            }
        }

        private void ThrowIfKeyExists(T key)
        {
            if (map.ContainsKey(key))
            {
                string message =
                   $"{MappingName}: " +
                   "Provided ENUM key is already present in OID mapping." +
                   $"Trying to assign ENUM key: {key.ToString()} but" +
                   $"current assigned OID value is: {map[key].ToString()}";
                throw new ArgumentException(message);
            }
        }

        private void ThrowIfKeyNotFound(ObjectIdentifier key)
        {
            if (!map.ContainsKey(key))
            {
                string message =
                   $"{MappingName}: " +
                   $"Not found mapping from OID to {typeof(T).Name} Type";
                   throw new KeyNotFoundException(message);
            }
        }

        private void ThrowIfKeyNotFound(T key)
        {
            if (!map.ContainsKey(key))
            {
                string message =
                   $"{MappingName}: " +
                   $"Not found mapping {typeof(T).Name} to OID";

                throw new KeyNotFoundException(message);
            }
        }
    }
}
