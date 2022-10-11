using Arctium.Standards.X509.X509Cert;
using System;
using System.Linq;

namespace Arctium.Standards.ASN1.Shared
{
    public class ChoiceObj<TKey> where TKey: struct
    {
        public struct TypeDef
        {
            public Type Type;
            public TKey Key;
            public bool AllowNull;

            public TypeDef(Type type, TKey key, bool allowNull = false)
            {
                Type = type;
                Key = key;
                AllowNull = allowNull;
            }
        }

        protected TypeDef[] definitions { get; private set; }

        private object obj;
        private TKey? key;

        protected ChoiceObj(TypeDef[] definition)
        {
            this.definitions = definition;
        }

        public virtual T GetStruct<T>() where T: struct
        {
            var type = typeof(T);

            foreach (var item in definitions)
            {
                if (item.Type == type) return (T)obj;
            }

            string msg = string.Format("Generic Argument 'T' ({0}) is invalid for this context. Valid types: {1}",
                type.Name,
                string.Join(", ", definitions.Select(d => d.Type.Name)));

            throw new ArgumentException(msg);
        }

        public virtual T Get<T>() where T: class
        {
            var type = typeof(T);

            foreach (var item in definitions)
            {
                if (item.Type == type) return obj as T;
            }

            string msg = string.Format("Generic Argument 'T' ({0}) is invalid for this context. Valid types: {1}",
                type.Name,
                string.Join(", ", definitions.Select(d => d.Type.Name)));

            throw new ArgumentException(msg);
        }

        internal void Set(TKey key, object obj)
        {
            ThrowIfTypeInvalid(obj, key);

            this.key = key;
            this.obj = obj;
        }

        protected void ThrowIfTypeInvalid(object obj, TKey a)
        {
            foreach (var item in definitions)
            {
                if (item.Key.Equals(a))
                {
                    if (item.AllowNull && obj == null) return;
                    if (item.Type == obj.GetType()) return;
                }
            }

            throw new ArgumentException("Current type is:");
        }
    }
}