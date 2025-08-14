using LibFreeVPN.Servers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace LibFreeVPN.Providers
{
    public class Cscdv : VPNProviderBase
    {
        // Android app, openvpn + ikev2 - we only care about openvpn due to unreliability of ikev2 clients.
        public override string Name => s_Name;
        private static readonly string s_Name = nameof(Cscdv);

        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS5kb3JhY29uZS5zdGFndnBu";

        public override string SampleVersion => "17.3.15";

        public override bool RiskyRequests => true;

        public override bool HasProtocol(ServerProtocol protocol)
        {
            return protocol == ServerProtocol.OpenVPN;
        }


        private static readonly string s_ConfigKey = Encoding.ASCII.GetString(Convert.FromBase64String("b3BuY29uZmln"));
        private static readonly string s_UsernameKey = Encoding.ASCII.GetString(Convert.FromBase64String("aWtldjJfdXNlcl9uYW1l"));
        private static readonly string s_PasswordKey = Encoding.ASCII.GetString(Convert.FromBase64String("aWtldjJfdXNlcl9wYXNzd29yZA=="));
        private static readonly string s_CountryKey = Encoding.ASCII.GetString(Convert.FromBase64String("c2VydmVyX25hbWU="));
        private static readonly string s_ArrayKey = Encoding.ASCII.GetString(Convert.FromBase64String("aWtldjJzZXJ2ZXJz"));
        private static IEnumerable<IVPNServer> ParseJson(JsonElement json)
        {
            var empty = Enumerable.Empty<IVPNServer>();
            return json.EnumerateArray().SelectMany((obj) =>
            {
                if (!obj.TryGetProperty(s_ConfigKey, out var config)) return empty;
                var configStr = config.GetString();
                if (string.IsNullOrEmpty(configStr)) return empty;
                if (!obj.TryGetProperty(s_UsernameKey, out var username)) return empty;
                if (!obj.TryGetProperty(s_PasswordKey, out var password)) return empty;

                var extraRegistry = CreateExtraRegistry(s_Name);
                extraRegistry.Add(ServerRegistryKeys.Username, username.GetString());
                extraRegistry.Add(ServerRegistryKeys.Password, password.GetString());

                if (obj.TryGetProperty(s_CountryKey, out var country))
                {
                    extraRegistry.Add(ServerRegistryKeys.Country, country.GetString());
                    extraRegistry.Add(ServerRegistryKeys.DisplayName, country.GetString());
                }

                return OpenVpnServer.ParseConfigFull(config.GetString(), extraRegistry);
            });
        }

        private static readonly string s_RequestUri = Encoding.ASCII.GetString(Convert.FromBase64String("aHR0cHM6Ly9zZXJ2ZXIuc3RhZ3Zwbi5jb20vYXBpL3YxL2FwcC1kYXRhLW5ldw=="));
        protected override async Task<IEnumerable<IVPNServer>> GetServersAsyncImpl()
        {
            // single POST request gives out some JSON.
            var httpClient = ServerUtilities.HttpClient;
            var content = await httpClient.GetStringAsync(s_RequestUri);
            var json = JsonDocument.Parse(content);

            if (json.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
            if (!json.RootElement.TryGetProperty(s_ArrayKey, out var array)) throw new InvalidDataException();
            if (array.ValueKind != JsonValueKind.Array) throw new InvalidDataException();

            return ParseJson(array).Distinct();
        }
    }
}
