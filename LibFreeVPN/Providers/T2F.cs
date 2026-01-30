using LibFreeVPN.Servers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace LibFreeVPN.Providers.T2F
{
    // Series of Android apps. Same developer, apps are named after country but the endpoints don't seem to match up for that.
    // Risky requests made, several C2 domains hardcoded.
    // One request to get the memecrypto method for making the interesting requests, one request to get all servers, one request per server to get a server config.
    // Only implemented three so far as it seems the same servers are shared by all of them.
    public abstract class T2FBase : VPNProviderBase
    {
        public override bool RiskyRequests => true;

        public override bool HasProtocol(ServerProtocol protocol)
        {
            return protocol == ServerProtocol.OpenVPN || protocol == ServerProtocol.WireGuard || protocol == ServerProtocol.V2Ray;
        }

        private static readonly string s_SettingsEndpoint = Encoding.ASCII.FromBase64String("c2V0dGluZ3M=");
        private static readonly string s_ServersEndpoint = Encoding.ASCII.FromBase64String("c2VydmVycw==");
        private static readonly string s_ServerEndpoint = Encoding.ASCII.FromBase64String("c2VydmVy");

        private static readonly string s_ApiKeyHeader = Encoding.ASCII.FromBase64String("YXBwLWlk");

        private static readonly Dictionary<ServerProtocol, string> s_ProtocolToEndpoint = new Dictionary<ServerProtocol, string>()
        {
            { ServerProtocol.OpenVPN, string.Empty },
            { ServerProtocol.WireGuard, Encoding.ASCII.FromBase64String("d2df") },
            { ServerProtocol.V2Ray, Encoding.ASCII.FromBase64String("c3Nf") }
        };

        private static readonly string[] s_DefaultC2Hosts =
        {
            Encoding.ASCII.FromBase64String("aHR0cHM6Ly9jdXAuaXBob25lZ2V0LmZ5aS9hcGkv"),
            Encoding.ASCII.FromBase64String("aHR0cHM6Ly9iaXAuYW5kcm9pZGNvbm5lY3QuZnlpL2FwaS8="),
            Encoding.ASCII.FromBase64String("aHR0cHM6Ly9nb2Zhc3RkaXJlY3QudG9wL2FwaS8="),
            Encoding.ASCII.FromBase64String("aHR0cHM6Ly9hcGkudGFwMmZyZWUubmV0L2FwaS8=")
        };

        protected virtual IEnumerable<string> C2Hosts { get; } = s_DefaultC2Hosts;

        protected abstract string C2Prefix { get; }

        protected virtual string C2ApiKey => Encoding.ASCII.FromBase64String("cmVld2dmZHM1dzRnZmJzNHc1aGZkbmhlNTZoZ25kaHQ=");

        protected virtual string MemecryptoKey1 => Encoding.ASCII.FromBase64String("ZXZ0ZWtiZTF1d3AweXo=");

        protected virtual string MemecryptoKey2 => Encoding.ASCII.FromBase64String("Z0w1TXI0UEwzZE5vQVg=");

        protected virtual string MemecryptoKey3 => Encoding.ASCII.FromBase64String("azFZT0dVSjhuODIwVHc=");

        protected virtual string MemecryptoKey4 => Encoding.ASCII.FromBase64String("OFJzSTIzNHV1ZDB1UTc=");

        protected virtual string MemecryptoKey5 => Encoding.ASCII.FromBase64String("S1JFQTZ6OHpVU1IxNGk=");

        private static string MD5Hash(string str)
        {
            using (var md5 = MD5.Create())
            {
                return BitConverter.ToString(md5.ComputeHash(Encoding.UTF8.GetBytes(str))).Replace("-", "").ToLower();
            }
        }

        private static string MD5Hash(StringBuilder sb) => MD5Hash(sb.ToString());

        protected string MemeHash(string value, int method)
        {
            if (method == 1)
            {
                var strToHash = new StringBuilder(value.Length * MemecryptoKey1.Length)
                    .Insert(0, value, MemecryptoKey1.Length);
                int offBase = MemecryptoKey1.Length / 2;
                for (int i = 0; i < MemecryptoKey1.Length / 2; i++) {
                    strToHash.Replace(MemecryptoKey1[i], MemecryptoKey1[offBase + i]);
                }
                return MD5Hash(strToHash);
            } else if (method == 2)
            {
                var strToHash = new StringBuilder(Math.Min(value.Length, MemecryptoKey2.Length) * 2);
                for (int i = 0; i < Math.Min(value.Length, MemecryptoKey2.Length); i++)
                {
                    bool isThird = (i % 3) == 0;
                    var chr1 = value[i];
                    var chr2 = MemecryptoKey2[i];
                    strToHash.Insert(0, isThird ? chr1 : chr2)
                        .Append(isThird ? chr2 : chr1);
                }
                return MD5Hash(strToHash);
            } else if (method == 3)
            {
                var strToHash = new StringBuilder((MemecryptoKey3.Length + value.Length) * 2)
                    .Append(MemecryptoKey3)
                    .Append(value);
                for (int i = 0; i < (value.Length - 1); i++)
                {
                    strToHash.Append(value[value.Length - i - 1]);
                }
                for (int i = 1; i < MemecryptoKey3.Length; i++)
                {
                    strToHash.Append(MemecryptoKey3[MemecryptoKey3.Length - i - 1]);
                }
                return MD5Hash(strToHash);
            } else if (method == 4)
            {
                var strToHash = new StringBuilder(value.Length + (MemecryptoKey4.Length * 2 * (value.Length / 4)));
                for (int i = 0; i < value.Length; i++)
                {
                    strToHash.Insert(0, value[i]);
                    if ((i % 4) != 0) continue;
                    strToHash.Insert(0, MemecryptoKey4).Append(MemecryptoKey4);
                }
                return MD5Hash(strToHash);
            } else if (method == 5)
            {
                var strToHash = new StringBuilder(value.Length + MemecryptoKey5.Length).Append(value);
                for (int i = 0; i < MemecryptoKey5.Length; i++)
                {
                    var cmp = new string(MemecryptoKey5[MemecryptoKey5.Length - i - 1], 1);
                    if ((i + 1) < MemecryptoKey5.Length) cmp += new string(MemecryptoKey5[MemecryptoKey5.Length - i - 2], 1);
                    if (value.Contains(cmp))
                    {
                        strToHash.Append(cmp);
                    } else
                    {
                        strToHash.Insert(0, cmp);
                    }
                }
                return MD5Hash(strToHash);
            }

            throw new ArgumentOutOfRangeException(nameof(method));
        }

        private async Task<string> MakeRequestAsync(string url, string apikey)
        {
            HttpResponseMessage listResponse = null;
            using (var listRequest = new HttpRequestMessage(HttpMethod.Get, url))
            {
                listRequest.Headers.Accept.ParseAdd("application/json");
                listRequest.Headers.Add(s_ApiKeyHeader, apikey);
                listResponse = await ServerUtilities.HttpClient.SendAsync(listRequest);
            }

            return await listResponse.Content.ReadAsStringAsync();
        }

        private async Task<IEnumerable<IVPNServer>> GetAndParseConfigAsync(string name, string country, string ip, string c2, string apikey, int method, ServerProtocol protocol)
        {
            try
            {
                // get the actual config from C2
                var conf = await MakeRequestAsync(string.Format("{0}{1}{2}{3}?ip={4}", c2, C2Prefix, s_ProtocolToEndpoint[protocol], s_ServerEndpoint, MemeHash(ip, method)), apikey);
                var json = JsonDocument.Parse(conf);
                if (json.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
                if (!json.RootElement.TryGetPropertyString("config", out var config)) throw new InvalidDataException();

                var registry = CreateExtraRegistry();
                registry.Add(ServerRegistryKeys.DisplayName, name);
                registry.Add(ServerRegistryKeys.Country, country);
                switch (protocol)
                {
                    case ServerProtocol.OpenVPN:
                        return OpenVpnServer.ParseConfigFull(config, registry);
                    case ServerProtocol.WireGuard:
                        return WireGuardServer.ParseConfigFull(config, registry);
                    case ServerProtocol.V2Ray:
                        return V2RayServer.ParseConfigFull(config, registry);
                    default:
                        throw new InvalidDataException();
                }
            } catch
            {
                return Enumerable.Empty<IVPNServer>();
            }
        }

        protected override async Task<IEnumerable<IVPNServer>> GetServersAsyncImpl()
        {
            // try each C2 in order:
            foreach (var c2 in C2Hosts)
            {
                try
                {
                    // get the config with the memecrypto method expected
                    var conf = await ServerUtilities.HttpClient.GetStringAsync(string.Format("{0}{1}{2}", c2, C2Prefix, s_SettingsEndpoint));
                    var json = JsonDocument.Parse(conf);
                    if (json.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
                    if (!json.RootElement.TryGetPropertyString("method", out var methodProp)) throw new InvalidDataException();
                    if (!int.TryParse(methodProp, out var method)) throw new InvalidDataException();

                    var apikey = MemeHash(C2ApiKey, method);

                    // get the list of servers for each supported protocol
                    var ret = Enumerable.Empty<IVPNServer>();
                    foreach (var protokv in s_ProtocolToEndpoint)
                    {
                        conf = await MakeRequestAsync(string.Format("{0}{1}{2}{3}", c2, C2Prefix, protokv.Value, s_ServersEndpoint), apikey);
                        json = JsonDocument.Parse(conf);
                        if (json.RootElement.ValueKind != JsonValueKind.Array) throw new InvalidDataException();
                        // parse each element
                        var tasks = json.RootElement.EnumerateArray().SelectMany((server) =>
                        {
                            var empty = Enumerable.Empty<Tuple<string, string, string>>();
                            if (!server.TryGetPropertyString("name", out var name)) return empty;
                            if (!server.TryGetPropertyString("country", out var country)) return empty;
                            if (!server.TryGetPropertyString("ip", out var ip)) return empty;
                            return new Tuple<string, string, string>(name, country, ip).EnumerableSingle();
                        }).Select((server) => GetAndParseConfigAsync(server.Item1, server.Item2, server.Item3, c2, apikey, method, protokv.Key)).ToList();
                        await Task.WhenAll(tasks);
                        ret = ret.Concat(tasks.SelectMany((task) => task.Result));
                    }
                    return ret;
                } catch { continue; }
            }

            return Enumerable.Empty<IVPNServer>();
        }
    }

    public sealed class T2FUS : T2FBase
    {
        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPXZwbi51c2FfdGFwMmZyZWU=";

        public override string SampleVersion => "3.139";

        private static readonly string[] s_C2Hosts =
        {
            Encoding.ASCII.FromBase64String("aHR0cHM6Ly9nZXRkYXRhZnJvbS50b3AvYXBpLw=="),
            Encoding.ASCII.FromBase64String("aHR0cHM6Ly9hbmRyb2lkdnBuLnRvcC9hcGkv"),
            Encoding.ASCII.FromBase64String("aHR0cHM6Ly9pb3N2cG4udG9wL2FwaS8="),
            Encoding.ASCII.FromBase64String("aHR0cHM6Ly9hcGkudGFwMmZyZWUubmV0L2FwaS8=")
        };

        protected override IEnumerable<string> C2Hosts => s_C2Hosts;

        protected override string C2Prefix => Encoding.ASCII.FromBase64String("dXNhLQ==");
    }

    public sealed class T2FID : T2FBase
    {
        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWluZG9uZXNpYS52cG5fdGFwMmZyZWU=";

        public override string SampleVersion => "1.182";

        protected override string C2Prefix => Encoding.ASCII.FromBase64String("aWQt");
    }

    public sealed class T2FIN : T2FBase
    {
        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWluZG9uZXNpYS52cG5fdGFwMmZyZWU=";

        public override string SampleVersion => "1.157";

        protected override string C2Prefix => Encoding.ASCII.FromBase64String("aW4t");
    }
}
