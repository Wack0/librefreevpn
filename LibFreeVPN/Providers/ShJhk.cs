using LibFreeVPN.Memecrypto;
using LibFreeVPN.Servers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

// Android apps. SocksHttp using SSH + OpenVPN.
// All of these by same developer, same github account used, xxtea + custom unicode rot.
namespace LibFreeVPN.Providers.ShJhk
{
    public abstract class ParserBase<TType> : SocksHttpWithOvpnParserTea<TType>
        where TType : ParserBase<TType>, new()
    {
        protected override string CountryNameKey => "FLAG";
        protected override string ServerTypeKey => "serverType";
        protected override string OvpnPortKey => "TcpPort";
        protected override string OvpnKey => "ovpnCertificate";

        protected override string OuterKey => InnerKey.ToString();
        protected abstract int InnerKey { get; }

        protected override string DecryptOuter(string ciphertext)
        {
            var arr = base.DecryptOuter(ciphertext).ToCharArray();
            for (int i = 0; i < arr.Length; i++) arr[i] -= (char)(InnerKey * 2);
            return new string(arr);
        }

        protected override string DecryptInner(string jsonKey, string ciphertext)
        {
            if (jsonKey == OvpnPortKey) return ciphertext.Split(':')[0];
            if (jsonKey != HostnameKey && jsonKey != UsernameKey && jsonKey != PasswordKey && jsonKey != OvpnKey && jsonKey != V2RayKey) return ciphertext;

            return DecryptOuter(ciphertext);
        }

        protected override IEnumerable<IVPNServer> ParseServer(JsonDocument root, JsonElement server, IReadOnlyDictionary<string, string> passedExtraRegistry)
        {
            string serverType = null;
            if (!server.TryGetProperty(ServerTypeKey, out var serverTypeJson)) throw new InvalidDataException();
            switch (serverTypeJson.ValueKind)
            {
                case JsonValueKind.String:
                    serverType = serverTypeJson.GetString();
                    break;
                case JsonValueKind.Number:
                    serverType = serverTypeJson.GetInt32().ToString();
                    break;
                default:
                    throw new InvalidDataException();
            }

            string hostname, port;
            string username = null, password = null, v2ray = null, ovpnconf = null;
            string name, country;

            if (!server.TryGetPropertyString(ServerNameKey, out name)) throw new InvalidDataException();
            if (!server.TryGetPropertyString(CountryNameKey, out country)) throw new InvalidDataException();
            if (!server.TryGetPropertyString(HostnameKey, out hostname)) throw new InvalidDataException();
            if (!server.TryGetPropertyString(OvpnPortKey, out port)) throw new InvalidDataException();

            var extraRegistry = new Dictionary<string, string>();
            foreach (var kv in passedExtraRegistry) extraRegistry.Add(kv.Key, kv.Value);
            extraRegistry.Add(ServerRegistryKeys.DisplayName, name);
            extraRegistry.Add(ServerRegistryKeys.Country, country);

            switch (serverType.ToLower())
            {
                case "0": // ovpn
                    if (!server.TryGetPropertyString(UsernameKey, out username)) throw new InvalidDataException();
                    if (!server.TryGetPropertyString(PasswordKey, out password)) throw new InvalidDataException();
                    if (!server.TryGetPropertyString(OvpnKey, out ovpnconf))
                    {
                        if (root.RootElement.TryGetPropertyString(OvpnKey, out ovpnconf)) ovpnconf = DecryptInner(OvpnKey, ovpnconf);
                        else ovpnconf = null;
                    }
                    if (string.IsNullOrEmpty(ovpnconf)) throw new InvalidDataException();
                    var ovpnRegistry = new Dictionary<string, string>();
                    foreach (var kv in extraRegistry) ovpnRegistry.Add(kv.Key, kv.Value);
                    ovpnRegistry.Add(ServerRegistryKeys.Username, username);
                    ovpnRegistry.Add(ServerRegistryKeys.Password, password);
                    return OpenVpnServer.ParseConfigFull(OpenVpnServer.InjectHostIntoConfig(ovpnconf, hostname, port), ovpnRegistry);
                case "1": // ssh
                    if (!server.TryGetPropertyString(UsernameKey, out username)) throw new InvalidDataException();
                    if (!server.TryGetPropertyString(PasswordKey, out password)) throw new InvalidDataException();
                    return new SSHServer(hostname, port, username, password, extraRegistry).EnumerableSingle<IVPNServer>();
                // 2 => dns
                case "3": // v2ray
                    if (!server.TryGetPropertyString(V2RayKey, out v2ray)) throw new InvalidDataException();
                    return V2RayServer.ParseConfigFull(v2ray, extraRegistry);
                // 4 => udp
                default:
                    throw new InvalidDataException();
            }
        }
    }
    public sealed class Parser4669 : ParserBase<Parser4669>
    {
        protected override int InnerKey => 4669;
    }

    public abstract class ShJhkBase<TParser> : VPNProviderBase
        where TParser : ParserBase<TParser>, new()
    {

        protected virtual string ConfigName => Encoding.ASCII.GetString(Convert.FromBase64String("dXBkYXRlcw=="));
        protected abstract string RepoName { get; }

        public override bool RiskyRequests => false;

        public override bool HasProtocol(ServerProtocol protocol) =>
            protocol == ServerProtocol.SSH || protocol == ServerProtocol.OpenVPN;



        protected override async Task<IEnumerable<IVPNServer>> GetServersAsyncImpl()
        {
            var httpClient = new HttpClient();
            // Get the single config file used here.
            var config = await httpClient.GetStringAsync(string.Format("https://raw.githubusercontent.com/{0}/main/{1}", RepoName, ConfigName));

            // And try to parse it
            var extraRegistry = CreateExtraRegistry(Name);
            return ParserBase<TParser>.ParseConfig(config, extraRegistry);
        }
    }

    public sealed class ShJk : ShJhkBase<Parser4669>
    {
        
        protected override string RepoName => Encoding.ASCII.GetString(Convert.FromBase64String("SkhLVlBOL0pL"));

        public override string Name => nameof(ShJk);

        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS5mYXN0dnBuLmpr";

        public override string SampleVersion => "2.2";

        public override bool RiskyRequests => false;
    }

    public sealed class ShJkV : ShJhkBase<Parser4669>
    {
        protected override string RepoName => Encoding.ASCII.GetString(Convert.FromBase64String("SkhLVlBOL0pWUE5WSVA="));

        public override string Name => nameof(ShJkV);

        public override string SampleSource => "aHR0cHM6Ly9naXRodWIuY29tL1RIQU5EQVJMSU4yMDE1L1Rlc3QvcmVsZWFzZXMvZG93bmxvYWQvdjIuMC4wL0pLLlZJUC5WUE5fMi4wLjAuYXBr";

        public override string SampleVersion => "2.0.0";

        public override bool RiskyRequests => false;
    }

    public sealed class ShMmt : ShJhkBase<Parser4669>
    {
        protected override string RepoName => Encoding.ASCII.GetString(Convert.FromBase64String("SkhLVlBOL01NVFZQTg=="));

        public override string Name => nameof(ShMmt);

        // No sample found - saw in repo list and observed to use the same memecrypto as the others here
        public override string SampleSource => "aHR0cHM6Ly9naXRodWIuY29tL0pIS1ZQTi9NTVRWUE4=";

        public override string SampleVersion => "N/A";

        public override bool RiskyRequests => false;
    }

    public sealed class ShKo : ShJhkBase<Parser4669>
    {
        protected override string RepoName => Encoding.ASCII.GetString(Convert.FromBase64String("SkhLVlBOL0tPS08="));

        public override string Name => nameof(ShKo);

        // No sample found - saw in repo list and observed to use the same memecrypto as the others here
        public override string SampleSource => "aHR0cHM6Ly9naXRodWIuY29tL0pIS1ZQTi9LT0tP";

        public override string SampleVersion => "N/A";

        public override bool RiskyRequests => false;
    }
}
