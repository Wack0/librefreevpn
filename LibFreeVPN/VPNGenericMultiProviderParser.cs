using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace LibFreeVPN
{
    /// <summary>
    /// Base class for a generic multi-provider parser
    /// </summary>
    /// <typeparam name="TParser">Object implementing this class</typeparam>
    public abstract class VPNGenericMultiProviderParser<TParser> : IVPNGenericMultiProviderParser
        where TParser : VPNGenericMultiProviderParser<TParser>, new()
    {
        private static readonly TParser s_Parser = new TParser();

        public abstract IEnumerable<IVPNServer> Parse(string config, IReadOnlyDictionary<string, string> extraRegistry);
        public static IEnumerable<IVPNServer> ParseConfig(string config)
        {
            return ParseConfig(config, new Dictionary<string, string>());
        }

        public static IEnumerable<IVPNServer> ParseConfig(string config, IReadOnlyDictionary<string, string> extraRegistry)
        {
            try
            {
                return s_Parser.Parse(config, extraRegistry).Distinct();
            }
            catch { return Enumerable.Empty<IVPNServer>(); }
        }
    }
    /// <summary>
    /// Base class for a multi-provider parser for a JSON object with an array of servers where 
    /// </summary>
    /// <typeparam name="TParser">Object implementing this class</typeparam>
    public abstract class VPNJsonArrInObjMultiProviderParser<TParser> : VPNGenericMultiProviderParser<TParser>
        where TParser : VPNJsonArrInObjMultiProviderParser<TParser>, new()
    {
        // Base object
        /// <summary>
        /// JSON key of the servers array.
        /// </summary>
        protected virtual string ServersArrayKey => "Servers";

        /// <summary>
        /// Enumerator over any additional (optional) servers arrays.
        /// </summary>
        protected virtual IEnumerable<string> OptionalServersArrayKeys => Enumerable.Empty<string>();

        /// <summary>
        /// Decrypt outer ciphertext (entire json object) if required
        /// </summary>
        /// <param name="ciphertext">Ciphertext</param>
        /// <returns>Plaintext</returns>
        protected virtual string DecryptOuter(string ciphertext) => ciphertext;

        /// <summary>
        /// Decrypt inner ciphertext (json string value) if required
        /// </summary>
        /// <param name="jsonKey">JSON object key</param>
        /// <param name="ciphertext">Ciphertext</param>
        /// <returns>Plaintext</returns>
        protected virtual string DecryptInner(string jsonKey, string ciphertext) => ciphertext;

        protected abstract IEnumerable<IVPNServer> ParseServer(JsonDocument root, JsonElement server, IReadOnlyDictionary<string, string> extraRegistry);

        private static bool MethodIsDerived(MethodInfo baseMethod, MethodInfo derivedMethod)
        {
            return baseMethod.DeclaringType != derivedMethod.DeclaringType && baseMethod.GetBaseDefinition() == derivedMethod.GetBaseDefinition();
        }

        private static readonly Type[] s_DecryptInnerArgs =
        {
            typeof(string), typeof(string)
        };

        private static readonly bool s_DecryptInnerIsDerived = MethodIsDerived(
            typeof(VPNJsonArrInObjMultiProviderParser<TParser>).GetMethod("DecryptInner", BindingFlags.Instance | BindingFlags.NonPublic, null, s_DecryptInnerArgs, null),
            typeof(TParser).GetMethod("DecryptInner", BindingFlags.Instance | BindingFlags.NonPublic, null, s_DecryptInnerArgs, null)
        );

        private JsonElement DecryptServer(JsonElement server)
        {
            if (server.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
            // If DecryptInner wasn't overridden then this is a no-op anyway.
            if (!s_DecryptInnerIsDerived) return server;
            var ret = new JsonObject();
            foreach (var elem in server.EnumerateObject())
            {
                if (elem.Value.ValueKind != JsonValueKind.String)
                {
                    // BUGBUG: any objects/arrays with crypted strings are still untouched here
                    ret.Add(elem.Name, JsonValue.Create(elem.Value));
                    continue;
                }

                ret.Add(elem.Name, DecryptInner(elem.Name, elem.Value.GetString()));
            }
            return JsonDocument.Parse(ret.ToJsonString()).RootElement;
        }

        private IEnumerable<IVPNServer> TryParseServer(JsonDocument root, JsonElement server, IReadOnlyDictionary<string, string> extraRegistry)
        {
            try
            {
                return ParseServer(root, DecryptServer(server), extraRegistry);
            }
            catch { return Enumerable.Empty<IVPNServer>(); }
        }

        public override sealed IEnumerable<IVPNServer> Parse(string config, IReadOnlyDictionary<string, string> extraRegistry)
        {
            // Decrypt outer ciphertext
            config = DecryptOuter(config);

            var json = JsonDocument.Parse(config);
            if (json.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException();

            if (!json.RootElement.TryGetProperty(ServersArrayKey, out var servers)) throw new InvalidDataException();
            if (servers.ValueKind != JsonValueKind.Array) throw new InvalidDataException();

            IEnumerable<JsonElement> serversEnum = servers.EnumerateArray();
            foreach (var key in OptionalServersArrayKeys)
            {
                if (!json.RootElement.TryGetProperty(key, out var optional)) continue;
                if (optional.ValueKind != JsonValueKind.Array) continue;
                serversEnum = serversEnum.Concat(optional.EnumerateArray());
            }

            return serversEnum.SelectMany((server) => TryParseServer(json, server, extraRegistry)).Distinct();
        }
    }
}
