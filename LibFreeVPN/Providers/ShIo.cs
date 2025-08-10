using LibFreeVPN.Memecrypto;
using LibFreeVPN.Servers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace LibFreeVPN.Providers
{
    // Android app. SocksHttp using SSH + v2ray.

    public sealed class ShIo : VPNProviderBase
    {
        private sealed class Parser : SocksHttpWithOvpnParserTea<Parser>
        {
            protected override string OvpnKey => "setOpenVPN";

            protected override string OuterKey => Encoding.ASCII.GetString(Convert.FromBase64String("YVolUlUlaXRSTUJeOCZVZQ=="));
        }

        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS5tb2JpbGVhcHAucm92cG4=";

        public override string SampleVersion => "4.0";

        public override bool RiskyRequests => true;

        public override bool HasProtocol(ServerProtocol protocol) =>
            protocol == ServerProtocol.SSH && protocol == ServerProtocol.V2Ray;

        private static readonly string s_RequestUri = Encoding.ASCII.GetString(Convert.FromBase64String("aHR0cHM6Ly9pb3Zwbi5tZS9hcHAvY29uZmlnL2hkaGRoZGRkZC5waHA="));


        protected override async Task<IEnumerable<IVPNServer>> GetServersAsyncImpl()
        {
            var httpClient = new HttpClient();
            // Get the single config file used here.
            var config = await httpClient.GetStringAsync(s_RequestUri);

            // And try to parse it
            var extraRegistry = CreateExtraRegistry();
            return Parser.ParseConfig(config, extraRegistry);
        }
    }
}
