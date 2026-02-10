using LibFreeVPN.ProviderHelpers;
using LibFreeVPN.Servers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

// Android apps, sockshttp fork with v2ray only.
// Risky requests made - C2 attempts to track users for being able to only send "premium" servers to paid users.
namespace LibFreeVPN.Providers.SocksHttp.ShV2x
{
    public sealed class Parser : SocksHttpParserAesPbkdf2<Parser>
    {
        protected override string ServersArrayKey => "servers";
        protected override string ServerNameKey => "name";
        protected override string CountryNameKey => "flag";
        protected override string V2RayKey => "Connection_Config";
        protected override string ServerTypeKey => "OTHER";

        protected override string OuterKeyId => Encoding.ASCII.FromBase64String("cFhQV1VqRm0waFc2MTJ0YXY1RXo=");
        protected override IEnumerable<IVPNServer> ParseServer(JsonDocument root, JsonElement server, IReadOnlyDictionary<string, string> passedExtraRegistry)
        {
            string name, country, v2ray;

            if (!server.TryGetPropertyString(ServerNameKey, out name)) throw new InvalidDataException();
            if (!server.TryGetPropertyString(CountryNameKey, out country)) throw new InvalidDataException();
            if (!server.TryGetProperty(V2RayKey, out var v2rayObj)) throw new InvalidDataException();
            if (v2rayObj.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
            if (!v2rayObj.TryGetPropertyString(ServerTypeKey, out v2ray)) throw new InvalidDataException();
            // no trusting the client here, "premium" servers give a dummy config for unregistered user:
            if (v2ray.StartsWith("vmess://eyJhZGQiOiI5OCIsImFpZCI6IjAiLC")) throw new InvalidDataException();

            var extraRegistry = new Dictionary<string, string>();
            foreach (var kv in passedExtraRegistry) extraRegistry.Add(kv.Key, kv.Value);
            extraRegistry.Add(ServerRegistryKeys.DisplayName, name);
            extraRegistry.Add(ServerRegistryKeys.Country, country);
            return V2RayServer.ParseConfigFull(v2ray, extraRegistry);
        }
    }

    public abstract class ProviderBase : VPNProviderHttpGetBase
    {
        protected override Task<IEnumerable<IVPNServer>> GetServersAsyncImpl(string config)
        {
            var index = config.LastIndexOf("<br />\n");
            if (index >= 0)
            {
                config = config.Substring(index + "<br />\n".Length);
            }

            return GetServersAsyncImpl<Parser>(config);
        }
    }

    public sealed class ShV2xNet : ProviderBase
    {
        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS52Mm5ldC52MnJheS52cG4=";

        public override string SampleVersion => "1.9.16.6";

        public override DateTime? PossiblyAbandoned => new DateTime(2026, 10, 10);

        protected override string RequestUri => Encoding.ASCII.FromBase64String(
            "aHR0cHM6Ly9hcGkudjJuZXQubGl2ZS92Mm5ldC92Mi9hcGkvbWFpbi5waHA/YWNjZXNzX3Rva2VuPSZHZXRTZXJ2ZXJMaXN0PSZkZWZ1YWx0U2VydmVySUQ9JmRldmljZV9pZD0maXNwPU1UTiZ2ZXJzaW9uPTU1NSZpc1BhcnRuZXJzaGlwPUZBTFNF"
        );

        public override bool HasProtocol(ServerProtocol protocol)
            => protocol == ServerProtocol.V2Ray;


    }
}
