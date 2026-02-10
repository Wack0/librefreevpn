using LibFreeVPN.ProviderHelpers;
using LibFreeVPN.Servers;
using System.Text;

namespace LibFreeVPN.Providers.SocksHttp
{
    // Android app. SocksHttp using SSH + OpenVPN.

    public sealed class ShEs : VPNProviderHttpGetBase<ShEs.Parser>
    {
        public sealed class Parser : SocksHttpWithOvpnParserAesGcmHkdf<Parser>
        {
            protected override string OuterKeyId => Encoding.ASCII.FromBase64String("bHswWyR+QTFncmczK2sxSGh5TUs3LklsRiFtJV5CMEFLZnFwT2MwZw==");
        }

        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS5taXNha2kuZXNhbnZwbg==";

        public override string SampleVersion => "1.4.5";

        public override bool HasProtocol(ServerProtocol protocol) =>
            protocol == ServerProtocol.SSH || protocol == ServerProtocol.OpenVPN;

        protected override string RequestUri => Encoding.ASCII.FromBase64String("aHR0cHM6Ly9lLXNhbi12cG4uaW4ubmV0L1VwZGF0ZS9lLXNhbi12cG4uanNvbg==");
    }
}
