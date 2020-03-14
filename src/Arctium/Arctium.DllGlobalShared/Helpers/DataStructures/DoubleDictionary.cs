using System.Collections;
using System.Collections.Generic;

namespace Arctium.DllGlobalShared.Helpers.DataStructures
{
    /// <summary>
    /// Provides bidirectional way of accessing key-value pair.
    /// Values can be used to get assigned keys and vice-versa.
    /// </summary>
    /// <typeparam name="A"></typeparam>
    /// <typeparam name="B"></typeparam>
    public class DoubleDictionary<A,B> : IDictionary<A,B>
    {
        Dictionary<A, B> forward;
        Dictionary<B, A> reverse;

        public DoubleDictionary()
        {
            forward = new Dictionary<A, B>();
            reverse = new Dictionary<B, A>();
        }

        public B this[A key]
        {
            get { return forward[key]; }
            set { Set(key, value); }
        }

        public A this[B key]
        {
            get { return reverse[key]; }
            set { Set(value, key); }
        }

        private void Set(A first, B second)
        {
            forward[first] = second;
            reverse[second] = first;
        }

        public ICollection<A> Keys => throw new System.NotImplementedException();

        public ICollection<B> Values => throw new System.NotImplementedException();

        public int Count => forward.Count;

        public bool IsReadOnly => false;

        public void Add(A key, B value)
        {
            Set(key, value);
        }

        public void Add(KeyValuePair<A, B> item)
        {
            throw new System.NotImplementedException();
        }

        public void Clear()
        {
            forward.Clear();
            reverse.Clear();
        }

        public bool Contains(KeyValuePair<A, B> item)
        {
            throw new System.NotImplementedException();
        }

        public bool ContainsKey(A key)
        {
            return forward.ContainsKey(key);
        }

        public bool ContainsKey(B key)
        {
            return reverse.ContainsKey(key);
        }

        public void CopyTo(KeyValuePair<A, B>[] array, int arrayIndex)
        {
            throw new System.NotImplementedException();
        }

        public IEnumerator<KeyValuePair<A, B>> GetEnumerator()
        {
            throw new System.NotImplementedException();
        }

        public bool Remove(A key)
        {
            throw new System.NotImplementedException();
        }

        public bool Remove(KeyValuePair<A, B> item)
        {
            throw new System.NotImplementedException();
        }

        public bool TryGetValue(A key, out B value)
        {
            return forward.TryGetValue(key, out value);
        }

        public bool TryGetValue(B key, out A value)
        {
            return reverse.TryGetValue(key, out value);
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            throw new System.NotImplementedException();
        }
    }
}
