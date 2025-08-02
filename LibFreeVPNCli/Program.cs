using CommandLine;
using CommandLine.Text;
using LibFreeVPN;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace LibFreeVPNCli
{
    public class Program
    {
        interface IBaseOptionsInclude
        {
            IEnumerable<ServerProtocol> IncludeProtocols { get; set; }
        }

        class BaseOptionsSearch : IBaseOptionsInclude
        {
            [Option('i', "include", HelpText = "Include only providers supporting these protocols (OpenVPN, WireGuard, V2Ray, SSHTunnel)")]
            public IEnumerable<ServerProtocol> IncludeProtocols { get; set; }

            [Option('e', "exclude", HelpText = "Exclude providers supporting these protocols (OpenVPN, WireGuard, V2Ray, SSHTunnel)")]
            public IEnumerable<ServerProtocol> ExcludeProtocols { get; set; }

            [Option('r', "risky", Default = false, HelpText = "Include providers that make risky requests (to servers ran by the developers of the sample, or entities involved with them)")]
            public bool AllowRiskyRequests { get; set; }

            public bool HasIncludeProtocols => IncludeProtocols.Any();
            public bool HasExcludeProtocols => ExcludeProtocols.Any();

            public IEnumerable<ServerProtocol> IncludeProtocolsFiltered => HasExcludeProtocols ? IncludeProtocols.Except(ExcludeProtocols) : IncludeProtocols;

            public IEnumerable<IVPNProvider> FilterProviders(IEnumerable<IVPNProvider> providers)
            {
                return providers.Where((prov) =>
                {
                    if (!AllowRiskyRequests && prov.RiskyRequests) return false;
                    if (HasIncludeProtocols)
                    {
                        return IncludeProtocolsFiltered.Any(prot => prov.HasProtocol(prot));
                    }
                    else if (HasExcludeProtocols)
                    {
                        return !ExcludeProtocols.Any(prot => prov.HasProtocol(prot));
                    }
                    return true;
                });
            }

            public IEnumerable<IVPNProvider> FilterProviders() => FilterProviders(VPNProviders.Providers);
        }

        interface IBaseOptionsGet
        {
            [Option('o', "output", HelpText = "Path to output configurations to (defaults to standard output)")]
            string OutputPath { get; set; }

            [Option('l', "long", HelpText = "Outputs long original configuration where relevant")]
            bool RequestOriginalConfig { get; set; }
        }

        class BaseOptionsGet : IBaseOptionsGet, IBaseOptionsInclude
        {
            public string OutputPath { get; set; }
            public bool RequestOriginalConfig { get; set; }

            [Option('i', "include", HelpText = "Include only servers of these protocols (OpenVPN, WireGuard, V2Ray, SSHTunnel)")]
            public IEnumerable<ServerProtocol> IncludeProtocols { get; set; }
        }

        class BaseOptionsGetSearch : BaseOptionsSearch, IBaseOptionsGet
        {
            public string OutputPath { get; set; }
            public bool RequestOriginalConfig { get; set; }
        }

        [Verb("list", HelpText = "List providers")]
        class ListOptions : BaseOptionsSearch { }

        [Verb("get", HelpText = "Get configs from single provider")]
        class GetOptions : BaseOptionsGet
        {
            [Value(0, Required = true, HelpText = "Provider name")]
            public string ProviderName { get; set; }
        }

        [Verb("getall", HelpText = "Get configs from multiple providers")]
        class GetAllOptions : BaseOptionsGetSearch { }

        static Task<int> ListProviders(ListOptions op)
        {
            foreach (var provider in op.FilterProviders())
            {
                Console.WriteLine(provider.Name);
                var protocols = (Enum.GetValues(typeof(ServerProtocol)) as ServerProtocol[]).Where((prot) => provider.HasProtocol(prot)).ToArray();
                Console.WriteLine("Protocols: {0}", string.Join(", ", protocols));
                if (provider.RiskyRequests) Console.WriteLine("Makes risky requests");
                Console.WriteLine();
            }
            return Task.FromResult(0);
        }

        static async Task<int> PerformGetOperation<TOperation>(TOperation op, IEnumerable<IVPNProvider> providers)
            where TOperation : IBaseOptionsGet, IBaseOptionsInclude
        {
            var tasks = providers.Select((prov) => prov.GetServersAsync()).ToArray();
            await Task.WhenAll(tasks);

            var servers = tasks.SelectMany((t) => t.Result);
            var dict = new Dictionary<string, int>();

            if (!string.IsNullOrEmpty(op.OutputPath) && !Directory.Exists(op.OutputPath)) Directory.CreateDirectory(op.OutputPath);

            foreach (var server in servers)
            {
                if (op.IncludeProtocols.Any() && !op.IncludeProtocols.Contains(server.Protocol)) continue;

                var dispNameWithProv = string.Format("{0}_{1}",
                    server.Registry[ServerRegistryKeys.ProviderName],
                    server.Registry[ServerRegistryKeys.DisplayName]);
                var dispName = string.Join("_", dispNameWithProv.Split(Path.GetInvalidFileNameChars()));
                var config = server.Config;
                var typeString = server.Protocol.ToString();
                if (op.RequestOriginalConfig && server.Registry.ContainsKey(ServerRegistryKeys.OriginalConfig))
                {
                    typeString = string.Format("{0}_{1}", typeString, server.Registry[ServerRegistryKeys.OriginalConfigType]);
                    config = server.Registry[ServerRegistryKeys.OriginalConfig];
                }
                int dispIdx = 0;
                if (dict.ContainsKey(dispName)) dispIdx = (++dict[dispName]);
                else dict.Add(dispName, 0);

                if (string.IsNullOrEmpty(op.OutputPath))
                {
                    if (dispIdx != 0) Console.WriteLine("[{0}] {1}_{2}", typeString, dispName, dispIdx);
                    else Console.WriteLine("[{0}] {1}", typeString, dispName);
                    Console.WriteLine();
                    Console.WriteLine(config);
                    Console.WriteLine();
                }
                else
                {
                    if (dispIdx != 0) dispName = string.Format("{0}_{1}", dispName, dispIdx);
                    var pathName = Path.Combine(op.OutputPath, string.Format("{0}.{1}.txt", dispName, typeString));
                    Console.WriteLine("Writing {0}...", pathName);
                    File.WriteAllText(pathName, config);
                }
            }
            return 0;
        }

        static Task<int> GetProvider(GetOptions op)
        {
            return PerformGetOperation(op, VPNProviders.Providers.Where((prov) => prov.Name == op.ProviderName));
        }

        static Task<int> GetAllProviders(GetAllOptions op)
        {
            return PerformGetOperation(op, op.FilterProviders());
        }

        public static async Task<int> Main(string[] args)
        {
            var parser = new Parser((ps) => { });
            var parsed = parser.ParseArguments<ListOptions, GetOptions, GetAllOptions>(args);

            parsed.WithNotParsed(_ =>
            {
                var helpText = HelpText.AutoBuild(parsed, h =>
                {
                    h.AutoVersion = false;
                    h.Copyright = string.Empty;
                    h.AddEnumValuesToHelpText = true;

                    return h;
                });
                Console.WriteLine(helpText);
            });

            return await parsed.MapResult(
                (ListOptions op) => ListProviders(op),
                (GetOptions op) => GetProvider(op),
                (GetAllOptions op) => GetAllProviders(op),
                errors => Task.FromResult(1));
        }
    }
}
