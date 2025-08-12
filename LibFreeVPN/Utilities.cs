using System;
using System.Collections.Generic;
using System.Collections.Specialized;
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
}
