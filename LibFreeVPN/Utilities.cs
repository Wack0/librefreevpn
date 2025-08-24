using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace LibFreeVPN
{
    /// <summary>
    /// Protocol of a VPN server
    /// </summary>
    public enum ServerProtocol
    {
        /// <summary>
        /// Protocol is unknown before the server-side configuration has been retrieved.
        /// </summary>
        Unknown,
        /// <summary>
        /// OpenVPN server
        /// </summary>
        OpenVPN,
        /// <summary>
        /// WireGuard server
        /// </summary>
        WireGuard,
        /// <summary>
        /// V2Ray (no matter the underlying protocol - vmess/vless/socks/...)
        /// </summary>
        V2Ray,
        /// <summary>
        /// SSH tunnel
        /// </summary>
        SSH,
    }

    public static class ServerRegistryKeys
    {
        /// <summary>
        /// Hostname or IP address of the VPN server
        /// If the config potentially uses some form of domain fronting supported by the client then this will be empty.
        /// </summary>
        public const string Hostname = "hostname";
        /// <summary>
        /// Port of the VPN server
        /// </summary>
        public const string Port = "port";
        /// <summary>
        /// Username to log in to the VPN server
        /// </summary>
        public const string Username = "username";
        /// <summary>
        /// Password to log in to the VPN server
        /// </summary>
        public const string Password = "password";
        /// <summary>
        /// Country where the VPN server is hosted in
        /// </summary>
        public const string Country = "country";
        /// <summary>
        /// Provider's display name of this VPN server.
        /// </summary>
        public const string DisplayName = "displayname";
        /// <summary>
        /// Name of provider that this VPN server was obtained from
        /// </summary>
        public const string ProviderName = "providername";
        /// <summary>
        /// Format of original config where provided (currently only for v2ray)
        /// </summary>
        public const string OriginalConfigType = "originalconfigtype";
        /// <summary>
        /// Original configuration where provided
        /// </summary>
        public const string OriginalConfig = "originalconfig";
    }

    internal static class ServerUtilities
    {
        public static IReadOnlyDictionary<string, string> EmptyRegistry { get; } = new Dictionary<string, string>();
        public static readonly string[] NewLines = new string[] { "\r\n", "\n" };
        public static readonly HttpClient HttpClient = new HttpClient();

        /// <summary>
        /// Gets a value from a dictionary, returning a default value if the key doesn't exist.<br/>
        /// If <typeparamref name="TValue"/> is <seealso cref="string"/> and <paramref name="defaultValue"/> is <seealso cref="null"/>, returns an empty string when the key doesn't exist.
        /// </summary>
        /// <typeparam name="TKey">Type of dictionary key</typeparam>
        /// <typeparam name="TValue">Type of dictionary value</typeparam>
        /// <param name="dictionary">Dictionary to read from</param>
        /// <param name="key">Key to read the value of</param>
        /// <param name="defaultValue">Default value to return if key does not exist</param>
        /// <returns>Value of dictionary key, or <paramref name="defaultValue"/> if the key does not exist.</returns>
        public static TValue GetValue<TKey, TValue>(this IReadOnlyDictionary<TKey, TValue> dictionary, TKey key, TValue defaultValue = default)
        {
            if (dictionary.TryGetValue(key, out var value)) return value;

            // for TValue==string, return empty string instead of null string
            if (typeof(TValue) == typeof(string) && (string)(object)defaultValue == null) return (TValue)(object)string.Empty;
            return defaultValue;

        }

        public static void AddNonNullValue<TKey, TValue>(this IDictionary<TKey, TValue> dictionary, TKey key, TValue value)
        {
            if (typeof(TValue) == typeof(string) && string.IsNullOrEmpty((string)(object)value)) return;
            else if (!typeof(TValue).IsValueType && value == null) return;

            dictionary.Add(key, value);
        }

        public static void AddNonNullValue(this NameValueCollection dictionary, string key, string value)
        {
            if (string.IsNullOrEmpty(value)) return;

            dictionary.Add(key, value);
        }

        public static void AddNonNullValue<TKey, TValue>(this IDictionary<TKey, TValue> dictionary, TKey key, TValue? value)
            where TValue : struct
        {
            if (!value.HasValue) return;
            dictionary.Add(key, value.Value);
        }

        public static bool TryGetPropertyString(this JsonElement element, string key, out string value)
        {
            value = default;
            if (!element.TryGetProperty(key, out var property)) return false;
            if (property.ValueKind != JsonValueKind.String) return false;
            value = property.GetString();
            return true;
        }

        public static IEnumerable<TValue> EnumerableSingle<TValue>(this TValue val) => new TValue[] { val };
    }

    internal static class LazySingleton<T>
    {
        private static class KeyedObjects<TValue>
        {
            internal static ConcurrentDictionary<(TValue, Func<TValue, T>), T> s_Objects = new ConcurrentDictionary<(TValue, Func<TValue, T>), T>();
        }

        private static class TypeKeyedObjects<TValue>
        {
            internal static ConcurrentDictionary<(Type, Func<TValue, T>), T> s_Objects = new ConcurrentDictionary<(Type, Func<TValue, T>), T>();
        }

        internal static ConcurrentDictionary<Func<T>, T> s_NonKeyedObjects = new ConcurrentDictionary<Func<T>, T>();

        private static T Intern(T v)
        {
            if (typeof(T) == typeof(string)) v = (T)(object)string.Intern((string)(object)v);
            return v;
        }

        private static T GetImpl(Func<T> key) => Intern(key());

        private static T GetImpl<TData>((TData, Func<TData, T>) key) => Intern(key.Item2(key.Item1));

        /// <summary>
        /// Gets a lazy singleton using the provided delegate, calling it to initialise if required. 
        /// </summary>
        /// <remarks>Should only be used when the delegate will only be called from one place, otherwise conflicts will occur.</remarks>
        /// <param name="func">Delegate that initialises and returns a value.</param>
        /// <returns>The initialised value.</returns>
        internal static T Get(Func<T> func)
        {
            return s_NonKeyedObjects.GetOrAdd(func, GetImpl);
        }

        /// <summary>
        /// Gets a lazy singleton using the provided delegate and data argument, calling it to initialise if required.
        /// </summary>
        /// <param name="func">Delegate that takes a single parameter to initialise and returns a value.</param>
        /// <param name="data">The parameter of the delegate, used to initialise the value.</param>
        /// <returns>The initialised value.</returns>
        internal static T Get<TData>(Func<TData, T> func, TData data)
        {
            return KeyedObjects<TData>.s_Objects.GetOrAdd((data, func), GetImpl);
        }

        /// <summary>
        /// Gets a lazy singleton through the type-keyed dictionary using the provided delegate and data argument, calling it to initialise if required.
        /// </summary>
        /// <param name="func">Delegate that takes a single parameter to initialise and returns a value.</param>
        /// <param name="data">The parameter of the delegate, used to initialise the value.</param>
        /// <returns>The initialised value.</returns>
        internal static T GetByType<TData>(Func<TData, T> func, TData data)
        {
            return TypeKeyedObjects<TData>.s_Objects.GetOrAdd((data.GetType(), func), (kv) => Intern(kv.Item2(data)));
        }
    }

    internal static class LazySingleton
    {
        internal static T SingleInstance<T>(this Func<T> func) => LazySingleton<T>.Get(func);

        internal static T SingleInstance<T, TData>(this TData data, Func<TData, T> func) => LazySingleton<T>.Get(func, data);

        internal static T SingleInstanceByType<T, TData>(this TData data, Func<TData, T> func) => LazySingleton<T>.GetByType(func, data);

        internal static byte[] FromBase64String(this string base64String) => LazySingleton<byte[]>.Get(Convert.FromBase64String, base64String);

        internal static string FromBase64String(this Encoding encoding, string base64string) => LazySingleton<string>.Get((data) => encoding.GetString(Convert.FromBase64String(data)), base64string);
    }
}
