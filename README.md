# librefreevpn

Get the VPN configs that "free VPN" mobile apps use without trusting or running their official clients.

Use those VPNs on any device which has a client for those protocols.

Any custom code for DPI/etc workarounds implemented in these clients (ie, websocket + domain fronting CDNs, for example) is not implemented here.

Library targets .NET Standard 2.0, command line application targets .NET Core 3.1, .NET 6, .NET 8 and .NET Framework 4.7.2, winforms application targets .NET 6, .NET 8 and .NET Framework 4.7.2.

(All builds for .NET Framework 4.7.2 should also run on mono.)

## Why?

I reverse engineer things. Sometimes I get bored, and "free VPN" mobile apps are somewhat interesting targets to look at.

They mainly tend to be wrappers around typical VPN/obfuscating proxy protocol clients (or in some cases SSH tunnel), getting configs from some remote C2 server.

Therefore, I decided to write a small library around reimplementing the core of these clients (that is, getting the configs). And implemented a few examples (from both Android and iOS targets).

## Library documentation

Get `VPNProviders.Providers`, run whatever LINQ queries you want, then call `GetServersAsync()` to actually make the network requests to get the configs from that provider.

Note that various strings are lightly obfuscated as a way to discourage the use of search engines/etc to find "interesting" constant strings here.

`RiskyRequests` is set to true if the C2 is a server run by/for the developers of the sample in question. If it's not true, then the C2 is a third-party server, like a big git forge, blog, social network or so on.

## Command line documentation

Command line help is available, see `freevpnc help` etc.

`freevpnc list` will only show providers with risky requests, and `freevpnc getall` will only make risky requests, if `-r` option is used.

However, `freevpn get` will always make risky requests, if that provider makes them, as the provider to get is specified on the command line in that case.

### Examples

Get all OpenVPN configs without risky requests: `freevpnc getall -i openvpn`

Get all OpenVPN and v2ray configs without risky requests: `freevpnc getall -i openvpn v2ray`

Get all configs except OpenVPN, without risky requests: `freevpnc getall -e openvpn`

List all providers that provide OpenVPN servers or SSH tunnels, including those that would make risky requests: `freevpnc list -i openvpn ssh -r`

Get all configs from provider `BeautyBird`: `freevpnc get BeautyBird`

## User interface documentation

- Choose wanted protocols from left box
- Optionally, enable risky requests
- Choose wanted providers from right box
- Click Get button
- Choose the corresponding server, and copy the config to clipboard or save to file.

## License

All code in this repository is under the AGPLv3 license, albeit the XXTEA implementation is derived from https://github.com/xxtea/xxtea-dotnet (MIT licensed).

AGPLv3 license was chosen to discourage certain types of people from using this codebase.  
If you want to use this codebase on any kind of "money site" or adware-filled mobile app - this means you!

