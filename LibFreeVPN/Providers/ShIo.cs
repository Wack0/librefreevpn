using LibFreeVPN.Memecrypto;
using LibFreeVPN.ProviderHelpers;
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

    public sealed class ShIo : VPNProviderHttpGetBase<ShIo.Parser>
    {
        public sealed class Parser : SocksHttpWithOvpnParserTea<Parser>
        {
            protected override string OvpnKey => "setOpenVPN";

            protected override string OuterKey => Encoding.ASCII.GetString(Convert.FromBase64String("YVolUlUlaXRSTUJeOCZVZQ=="));
        }

        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS5tb2JpbGVhcHAucm92cG4=";

        public override string SampleVersion => "4.0";

        public override bool HasProtocol(ServerProtocol protocol) =>
            protocol == ServerProtocol.SSH || protocol == ServerProtocol.V2Ray;

        protected override string RequestUri => Encoding.ASCII.GetString(Convert.FromBase64String("aHR0cHM6Ly9pb3Zwbi5tZS9hcHAvY29uZmlnL2hkaGRoZGRkZC5waHA="));
    }
}
