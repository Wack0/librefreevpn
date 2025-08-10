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

namespace LibFreeVPN.Providers
{
    // Android app. SocksHttp using SSH + OpenVPN.

    public sealed class ShEs : VPNProviderBase
    {
        private sealed class Parser : SocksHttpWithOvpnParserTea<Parser>
        {
            protected override string OvpnKey => "setOpenVPN";

            protected override string OuterKey => Encoding.ASCII.GetString(Convert.FromBase64String("YU5MY0cyRlQ2OXZBQk5CcQ=="));
        }

        public override string Name => nameof(ShEs);

        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS5taXNha2kuZXNhbnZwbg==";

        public override string SampleVersion => "1.3.6";

        public override bool RiskyRequests => true;

        public override bool HasProtocol(ServerProtocol protocol) =>
            protocol == ServerProtocol.SSH && protocol == ServerProtocol.OpenVPN;

        private static readonly string s_RequestUri = Encoding.ASCII.GetString(Convert.FromBase64String("aHR0cHM6Ly9lLXNhbi12cG4uaW4ubmV0L1VwZGF0ZS9lLXNhbi12cG4uanNvbg=="));


        protected override async Task<IEnumerable<IVPNServer>> GetServersAsyncImpl()
        {
            var httpClient = new HttpClient();
            // Get the single config file used here.
            var config = await httpClient.GetStringAsync(s_RequestUri);

            // And try to parse it
            var extraRegistry = CreateExtraRegistry(Name);
            return Parser.ParseConfig(config, extraRegistry);
        }
    }
}
