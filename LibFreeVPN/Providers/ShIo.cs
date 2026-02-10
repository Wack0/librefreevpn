using LibFreeVPN.ProviderHelpers;
using LibFreeVPN.Servers;
using System.Text;

namespace LibFreeVPN.Providers.SocksHttp
{
    // Android app. SocksHttp using SSH + v2ray.

    public sealed class ShIo : VPNProviderHttpGetBase<ShIo.Parser>
    {
        public sealed class Parser : SocksHttpWithOvpnParserAesGcmHkdf<Parser>
        {
            protected override string OuterKeyId => Encoding.ASCII.FromBase64String("VUVEJXRTXnllVVhJe0M9LGlfWSNKNStWYn11Rm5Bejg7fTcpbjgpUGFUT2U5Nz0uMyU=");
        }

        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS5tb2JpbGVhcHAucm92cG4=";

        public override string SampleVersion => "5.1";

        public override bool HasProtocol(ServerProtocol protocol) =>
            protocol == ServerProtocol.SSH || protocol == ServerProtocol.OpenVPN;

        protected override string RequestUri => Encoding.ASCII.FromBase64String("aHR0cHM6Ly9pb3Zwbi5tZS9hcHAvY29uZmlnL2Rkcm92MmpzaHdoZWhzLnBocA==");
    }
}
