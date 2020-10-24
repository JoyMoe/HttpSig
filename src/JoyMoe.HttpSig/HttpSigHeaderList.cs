using System;
using System.Collections;
using System.Collections.Generic;

namespace JoyMoe.HttpSig
{
    public class HttpSigHeaderList : IEnumerable<string>
    {
        private readonly List<string> _items = new List<string>();

        private static string Normalize(string item)
        {
            if (string.IsNullOrWhiteSpace(item))
            {
                return string.Empty;
            }

#pragma warning disable CA1308 // Normalize strings to uppercase
            return item.ToLowerInvariant();
#pragma warning restore CA1308 // Normalize strings to uppercase
        }

        public bool TryAdd(string item)
        {
            if (Contains(item))
            {
                return false;
            }

            Add(item);

            return true;
        }

        public void AddRange(IEnumerable<string> items)
        {
            if (items == null)
            {
                throw new ArgumentNullException(nameof(items));
            }

            foreach (var item in items)
            {
                TryAdd(item);
            }
        }

        public void Add(string item)
        {
            item = Normalize(item);

            _items.Add(item);
        }

        public bool Contains(string item)
        {
            item = Normalize(item);

            return _items.Contains(item);
        }

        public void Clear()
        {
            _items.Clear();
        }

        public bool Remove(string item)
        {
            item = Normalize(item);

            return _items.Remove(item);
        }

        public int Count => _items.Count;

        public IEnumerator<string> GetEnumerator()
        {
            return _items.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        public override string ToString()
        {
            return string.Join(' ', _items);
        }

        public static implicit operator string(HttpSigHeaderList? list)
        {
            return list?.ToString() ?? "";
        }
    }
}
