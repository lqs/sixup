# Standards

sixup is built to the RFCs for IPv6 home routers. This page lists what each of them asks and how
far sixup goes, every item of them, gaps included. MUST, SHOULD and MAY are the RFCs' own words.

The sixup column uses these words.

| Word | Meaning |
|---|---|
| 🟢 Done, Passes | sixup does what the item asks. For a test, as far as reading the code shows |
| 🔵 Likely passes | The code should pass the test, with a detail not certain |
| 🟡 Partly | Some of what the item asks is done, and the rest is said |
| ⌛ Not yet | Not done, and meant to be |
| 🔴 Not done | Not done, with no plan to |
| 🙅 Not done on purpose, Deviates by design | Not done, for the reason given |
| ➖ Not applicable | The item asks for something sixup does not have or offer, or only permits something |
| 🐧 Kernel | The Linux stack does it, not sixup |

The Tested by column names the tests that would fail if sixup stopped doing what the row says,
unit tests and those against the kernel alike. None means no test covers it yet.

## Home routers as a whole

### RFC 7084, Basic Requirements for IPv6 Customer Edge Routers

The requirements a home router has to meet towards the ISP (W, WAA, WPD) and the LAN (L), with
ULA, security (S) and the transition sections on top.

| ID | What it asks | sixup | Tested by |
|---|---|---|---|
| G-1 | Be an IPv6 node as RFC 6434 describes (MUST) | 🐧 Kernel. The Linux stack is one | None |
| G-2 | Implement ICMPv6, point-to-point links as RFC 4443 section 3.1 says (MUST) | 🐧 Kernel | None |
| G-3 | Forward nothing between LAN and WAN until address and prefix are acquired (MUST NOT) | 🟢 Done. The filter lets through only traffic from and to the LAN and delegated prefixes, which are none before the line hands one out, unless `-source-filter=false` | `TestFirewallBorderAgainstKernel` |
| G-4 | Router Lifetime 0 on the LAN while the WAN has no default router (MUST) | 🟢 Done. The RA client reports whether the WAN has one, a PPP device route counting as one | `TestRARouterLifetime`, `TestRouteDefaultVia` |
| G-5 | Losing the WAN default router invalidates the router on the LAN at once (MUST) | 🟢 Done. Its expiry, a lifetime of 0 or the WAN link going down sends RAs with lifetime 0 at once, and so does exit | `TestRARouterLifetime`, `TestStoreWANRouterLossSkipsSettle`, `TestRAClientKeepsPrefixesOverALinkDown` |
| W-1 | Act as a host on the WAN for SLAAC or DHCPv6 addressing (MUST) | 🟢 Done | None |
| W-2 | Finish DAD on the link-local address before sending RS, and send RS from it (MUST) | 🟢 Done, as the kernel does not let a tentative address send | None |
| W-3 | Install the default route from Router Discovery (MUST) | 🟢 Done, a route per router with the metric following its preference | `TestRouterMetricAndRank`, `TestRouterMetrics` |
| W-4 | Act as a requesting router for DHCPv6-PD (MUST) | 🟢 Done | `TestApplyReply`, `TestDHCPv6ClientAgainstKernel`, `TestDHCPv6ClientStartsOnTheRAAgainstKernel` |
| W-5 | Keep the DUID across restarts (MUST) | 🟢 Done, stored in the state directory | `TestDUIDPersists` |
| W-6 | A PCP client on the WAN (SHOULD) | 🔴 Not done. sixup has a PCP server for the LAN | None |
| WLL-1 | IPv6 over Ethernet, RFC 2464, when the WAN is Ethernet (MUST) | 🐧 Kernel | None |
| WLL-2 | IPv6 over PPP, RFC 5072, when the WAN is PPP (MUST) | ➖ Not applicable. PPP is pppd's, sixup runs on its device | None |
| WLL-3 | IPCP and IPV6CP independent of each other on one PPP link (MUST) | ➖ Not applicable, as WLL-2 | None |
| WAA-1 | SLAAC on the WAN (MUST) | 🟢 Done | `TestParseRAPrefixes` |
| WAA-2 | Handle the L flag as RFC 5942 says (MUST) | 🟢 Done. An address from a prefix with L=0 is a /128, so no on-link route comes with it | `TestWANAddressOffLink` |
| WAA-3 | DHCPv6 client (MUST) | 🟢 Done | `TestApplyReply` |
| WAA-4 | IA_NA, Reconfigure Accept and DNS servers in DHCPv6 (MUST), search list (SHOULD) | 🟢 Done, Reconfigure authenticated | `TestApplyReply`, `TestParseCommon`, `TestReconfigureAuth`, `TestReconfigureRoundTrip` |
| WAA-5 | NTP, with the NTP server option (SHOULD) | 🟡 Partly. The NTP and SNTP servers are requested and passed on to the LAN; the router's own clock is left to the system | `TestServerPassesNTPOn` |
| WAA-6 | Request IA_NA when the RA sets M (MUST) | 🟢 Done, IA_NA is requested by default | `TestDHCPv6ClientStartsOnTheRAAgainstKernel` |
| WAA-7 | Take a global address from the delegation when the WAN has none (MUST) | 🟢 Done. Without SLAAC or IA_NA the WAN takes /128s in the first LAN's delegated /64, which temporary addresses use in any case | `TestStoreWANSubnet`, `TestAddressInWANSubnetAgainstKernel`, `TestAddressTemporaryInWANSubnetAgainstKernel` |
| WAA-8 | Support and request SOL_MAX_RT (MUST) | 🟢 Done | `TestParseCommon` |
| WAA-9 | Weak host model (MUST) | 🐧 Kernel, the Linux default | None |
| WAA-10 | Information Refresh Time (SHOULD) | 🟢 Done, requested and honoured | None |
| WPD-1 | IA_PD as a requesting router, RFC 3633 (MUST) | 🟢 Done | `TestApplyReply`, `TestDHCPv6ClientAgainstKernel` |
| WPD-2 | A size hint, large enough for one /64 per interface, configurable (MAY, MUST, SHOULD) | 🟢 Done, a /56 hint by default, `-dhcp6c-pd-len` | `TestPDHintRetry` |
| WPD-3 | Accept a size other than the hint, and log one too small (MUST, SHOULD) | 🟢 Done | `TestPDHintRetry`, `TestSingle64WithSeveralLANs` |
| WPD-4 | Start PD when the RA sets M or O (MUST) | 🟢 Done, and PD is tried when both are 0 too | `TestDHCPv6ClientStartsOnTheRAAgainstKernel` |
| WPD-5 | Drop traffic for the unassigned part of the delegation (MUST) | 🟢 Done with an unreachable route. The kernel answers with ICMPv6 code 0 | `TestRouteUnreachableAgainstKernel` |
| WPD-6 | Accept IA_PD in a reply without addresses (MUST) | 🟢 Done | `TestApplyReply`, `TestSixupBehindSixup` |
| WPD-7 | Run no dynamic routing protocol on the WAN (MUST NOT) | 🟢 Done | None |
| WPD-8 | Prefix Exclude, RFC 6603 (SHOULD) | 🟢 Done. The excluded part goes to no LAN and no downstream router, and a LAN on it is warned about | `TestParsePDExclude`, `TestStoreSkipsTheExcludedSubnet` |
| ULA-1 | Be able to generate a ULA prefix (SHOULD) | 🟢 Done, `-ula auto` | `TestStoreULA` |
| ULA-2 | Keep the ULA prefix across restarts and power loss (MUST, when generated) | 🟢 Done, stored in the state directory | `TestStoreULA` |
| ULA-3 | The ULA prefix configurable (SHOULD) | 🟢 Done, `-ula` takes a prefix | None |
| ULA-4 | Act as a site border router for ULA by default (MUST) | 🟢 Done, in every `-unsolicited` mode. A ULA the upstream advertises is of the same site and crosses the WAN, as RFC 4193 section 4.3 allows; one of another site sent from the LAN is refused with ICMPv6 code 1. Other interfaces are checked after source NAT, so that the operator's NAT66 works, and a ULA left untranslated is dropped; what the operator's NAT forwards in, a published port or a reply, passes | `TestFirewallBorderAgainstKernel`, `TestFirewallSourceFilterOffAgainstKernel`, `TestFirewallOtherInterfaceAgainstKernel`, `TestRAClientReportsUpstreamULA` |
| ULA-5 | No default router while only ULA prefixes are advertised (MUST NOT) | 🟢 Done | `TestRARouterLifetime` |
| L-1 | Router behaviour of RFC 4861 (MUST) | 🟢 Done | None |
| L-2 | A separate /64 per LAN, from the delegation and the ULA (MUST) | 🟢 Done | `TestSplitLAN`, `TestStoreLifecycle`, `TestStoreULA` |
| L-3 | Advertise the delegated prefix and the ULA in a Route Information Option (MUST) | 🟢 Done, whether or not the router is a default router; a delegation gone is withdrawn with lifetime 0 | `TestRAAdvertisesTheDelegationAndULA`, `TestRAAdvertisesADelegated64` |
| L-4 | No default router while no prefix is configured or delegated (MUST NOT) | 🟢 Done | `TestRABuildNoPrefixNoUpstream`, `TestRANoDefaultRouterOnStalePrefixes` |
| L-5 | Every LAN interface an advertising interface (MUST) | 🟢 Done | None |
| L-6 | A and L set by default (MUST) | 🟢 Done | `TestRABuildPrefixAndDNS` |
| L-7 | A and L configurable (SHOULD) | 🟢 Done, `-ra-slaac` and `-ra-onlink` | `TestRAPIOFlags` |
| L-8 | A stateful or stateless DHCPv6 server (MUST) | 🟢 Done, `-dhcp6s-mode` | `TestServerInformationRequest`, `TestServerSolicitRequestCommit` |
| L-9 | M off and O on unless addresses come from DHCPv6 (SHOULD) | 🟢 Done | None |
| L-10 | DNS servers and search list in DHCPv6 (MUST) | 🟢 Done | `TestServerInformationRequest` |
| L-11 | RDNSS and DNSSL in the RA (MUST) | 🟢 Done | `TestRABuildPrefixAndDNS`, `TestRABuildOverridesAndExtras` |
| L-12 | Pass WAN DHCPv6 options on to the LAN (SHOULD) | 🟢 Done. DNS servers, search list, NTP and SNTP servers, and the SIP servers of RFC 3319 to the hosts that ask, which completes the configuration options of RFC 3736 section 5.3 | `TestServerInformationRequest`, `TestServerPassesNTPOn`, `TestServerPassesSIPOn`, `TestParseCommon` |
| L-13 | A replaced prefix is advertised at once with preferred lifetime 0 (MUST) | 🟢 Done, with valid lifetime 0 too as RFC 9096 asks, for `-lan-deprecate-hold` | `TestRABuildDeprecatedPrefix`, `TestStoreLifecycle`, `TestLifetimeClamp`, `TestRAWithdrawsStalePrefixes` |
| L-14 | ICMPv6 code 5 for traffic from an invalidated prefix (MUST) | 🟢 Done, for any source outside the LAN and delegated prefixes, unless `-source-filter=false` | `TestFirewallBorderAgainstKernel` |
| 6RD-1 | 6rd configured from DHCPv4 option 212 (MUST, when 6rd is supported) | ➖ Not applicable. sixup has no 6rd | None |
| 6RD-2 | 6rd configured by hand when IPv4 comes over PPP (MUST, when supported) | ➖ Not applicable | None |
| 6RD-3 | 6rd in hub and spoke mode when configured otherwise (MUST, when supported) | ➖ Not applicable | None |
| 6RD-4 | 6rd and native IPv6 WAN interfaces alone or together (MUST, when supported) | ➖ Not applicable | None |
| 6RD-5 | The source of each packet from the prefix of its WAN interface (MUST, when supported) | ➖ Not applicable | None |
| 6RD-6 | Different or identical prefixes on each WAN interface (MUST, when supported) | ➖ Not applicable | None |
| 6RD-7 | Native IPv6 preferred over 6rd on a tie (MUST, when supported) | ➖ Not applicable | None |
| DLW-1 | DS-Lite from the DHCPv6 option of RFC 6334 (MUST, when supported) | 🟢 Done | `TestAFTRResolvesThroughTheLineDNS`, `TestParseFQDN` |
| DLW-2 | No NAT on IPv4 carried by DS-Lite (MUST NOT) | 🟢 Done | `TestNATAgainstKernelDSLite`, `TestNATPlanPerLineType` |
| DLW-3 | Turn the B4 off when the WAN has an IPv4 address (SHOULD) | 🟡 Partly. The tunnel's IPv4 route has a high metric, so native IPv4 wins | None |
| S-1 | The simple security of RFC 6092 (SHOULD) | 🟢 Done, see below | `TestFirewallAgainstKernel` |
| S-2 | Ingress filtering of LAN sources, BCP 38 (SHOULD) | 🟢 Done, on by default and off with `-source-filter=false`, as the 7084bis draft asks. Other interfaces are checked after source NAT | `TestFirewallBorderAgainstKernel`, `TestFirewallSourceFilterOffAgainstKernel`, `TestFirewallOtherInterfaceAgainstKernel` |
| S-3 | Filter what comes out of a tunnel (SHOULD) | 🟡 Partly. The filter covers IPv6 from the WAN; IPv4 from the tunnel meets only the NAT | None |

### RFC 9096, Requirements for CE Routers to Support Renumbering

What a home router has to do so that the LAN notices when the ISP renumbers it.

| ID | What it asks | sixup | Tested by |
|---|---|---|---|
| WPD-9 | Do not release the prefix on restart (SHOULD NOT) | 🟢 Done, unless `-dhcp6c-release` | None |
| WPD-10 | Keep the IAID across restarts (MUST) | 🟢 Done. It comes from the MAC address, or on an interface without one, such as PPP, from the MD5 of its name as in OpenWrt | `TestIAIDWithoutMAC` |
| L-13 | Signal stale prefixes to the LAN (MUST) | 🟢 Done for SLAAC, see the lines below | `TestRAWithdrawsStalePrefixes`, `TestStoreWithdrawsPrefixesFromBeforeRestart` |
|  | Record the advertised prefixes on stable storage (SHOULD) | 🟢 Done, in the state directory. After a restart, those the line does not hand out again are withdrawn as soon as it hands out any, so a prefix that comes back is never taken from the hosts | `TestStoreWithdrawsPrefixesFromBeforeRestart` |
|  | Advertise a stale prefix with preferred and valid lifetime 0, for as long as hosts may hold it (MUST) | 🟢 Done, for `-lan-deprecate-hold`, 90 minutes by default, which is ND_VALID_LIMIT | `TestRAWithdrawsStalePrefixes`, `TestStoreLifecycle` |
|  | Advertise the sub-prefixes of a delegation with valid lifetime 0 likewise (MUST) | 🟢 Done, as the delegation leaving is a withdrawal like any other | `TestRAWithdrawsStalePrefixes`, `TestStoreLifecycle` |
|  | Record DHCPv6 bindings on stable storage (SHOULD) | 🟢 Done | `TestServerLeaseFileRoundTrip`, `TestPDLeaseFileRoundTrip` |
|  | Return stale addresses and prefixes with lifetime 0 in DHCPv6 replies (MUST) | 🟢 Done | `TestServerRebindAfterPrefixChange`, `TestServerDelegationAfterPrefixChange` |
|  | Send Reconfigure to clients of a stale prefix (MUST, where possible) | 🟢 Done, for addresses and delegations, with one key per client | `TestReconfigureRoundTrip`, `TestDelegationCarriesTheReconfigureKey` |
| L-15 | LAN lifetimes never exceed what is left of the WAN delegation (MUST) | 🟢 Done | `TestServerDelegationLifetimeCap`, `TestRABuildOverridesAndExtras` |
| L-16 | Cap the LAN lifetimes at ND_PREFERRED_LIMIT and ND_VALID_LIMIT, 45 and 90 minutes (SHOULD) | 🟢 Done. Router Lifetime 45 minutes by default; PIO, RIO and DHCPv6 lifetimes capped; RDNSS and DNSSL shorter still | `TestRABuildPrefixAndDNS`, `TestRAAdvertisesTheDelegationAndULA` |

## IPv6 Ready CE Router tests

The [IPv6 Ready Logo](https://www.ipv6ready.org/resources/cpe.html) program tests CE routers
with the [CE Router Conformance Test Specification](https://www.ipv6ready.org/docs/CE_Router_Conformance.pdf),
revision 1.0.5 of 2024, by the IPv6 Forum and UNH-IOL. Its tests follow RFC 7084 and the RFCs
for DHCPv6, ND, SLAAC, ICMPv6 and path MTU. sixup has not been run against the test suite. The
table below comes from reading each test against the code, in September 2026, and lists all 173.
Most of the tests of ND states, path MTU, fragments, extension headers and forwarding exercise
the Linux stack alone.

| Test | Title | sixup | Tested by |
|---|---|---|---|
| 1.1.1 | Basic Message Exchange | 🟢 Passes. In part B a Confirm is sent only without a delegation; with one, as in the test setup, a Rebind is, as RFC 8415 section 18.2.12 asks | `TestDHCPv6ClientAgainstKernel`, `TestDHCPv6ClientDeclinesAgainstKernel`, `TestDHCPv6ClientConfirmsAgainstKernel` |
| 1.1.2 | Implementation of DHCP constants | 🟢 Passes | `TestNextRT` |
| 1.1.3 | DHCPv6 Option Format | 🟢 Passes | None |
| 1.1.4 | Client DHCP Unique Identifier Contents | 🟢 Passes | None |
| 1.1.5 | Elapsed Time Option Format | 🟡 Partly. A Confirm is sent only without a delegation, as in 1.1.10 | `TestDHCPv6ClientDeclinesAgainstKernel`, `TestDHCPv6ClientConfirmsAgainstKernel` |
| 1.1.6 | Identity Association Consistency | 🟢 Passes | None |
| 1.1.7 | Transmission of Solicit Messages | 🟢 Passes | `TestNextRT` |
| 1.1.8 | Message Exchange Termination for Solicit messages | 🟢 Passes | None |
| 1.1.9 | Transmission of Request message | 🟢 Passes | None |
| 1.1.10 | Transmission of Confirm messages | 🟡 Partly. Passes without a delegation, `-dhcp6c-pd-len 0`; with one, as in the test setup, a Rebind with the parameters of the Confirm is sent instead, as RFC 8415 section 18.2.12 asks | `TestDHCPv6ClientConfirmsAgainstKernel` |
| 1.1.11 | Transmission of Renew messages | 🟢 Passes | `TestDHCPv6ClientAgainstKernel` |
| 1.1.12 | Transmission of Rebind message | 🟢 Passes | None |
| 1.1.13 | Transmission of Release messages | 🟡 Partly. Release only on exit, within 3 to 4 seconds so that exit is not delayed | None |
| 1.1.14 | Transmission of Decline messages | 🟢 Passes. An IA_NA address that fails DAD is removed and declined | `TestDHCPv6ClientDeclinesAgainstKernel` |
| 1.1.15 | Reception of Advertise messages | ⌛ Not yet. An Advertise that assigns nothing ends the Solicit | None |
| 1.1.16 | Client Initiated Exchange – Reception of a Reply message | 🟡 Partly. A Reply with a status other than Success, or without an IA, is not handled as RFC 8415 section 18.2.10 says | `TestApplyReply` |
| 1.1.17 | Reception of Reply messages for DNS Configuration options | 🙅 Not done on purpose. The router's own resolver is the system's | None |
| 1.1.18 | Reception of Invalid Advertise message | 🟢 Passes | `TestClientValidation` |
| 1.1.19 | Reception of Invalid Reply message | 🟢 Passes | `TestClientValidation` |
| 1.1.20 | Client Message Validation | 🟢 Passes | None |
| 1.1.21 | SOL_MAX_RT Option | 🟡 Partly. SOL_MAX_RT is read from a Reply only, and an Advertise that assigns nothing ends the Solicit | `TestParseCommon` |
| 1.2.1 | Prefix Options Format | 🟢 Passes | None |
| 1.2.2 | Basic Message Exchange | 🟢 Passes | `TestDHCPv6ClientAgainstKernel` |
| 1.2.3 | Transmission of Solicit Messages for Prefix Delegation | 🟢 Passes | None |
| 1.2.4 | Transmission of Request message for Prefix Delegation | 🟢 Passes | None |
| 1.2.5 | Transmission of Renew messages for Prefix Delegation | 🟢 Passes | `TestDHCPv6ClientAgainstKernel` |
| 1.2.6 | Transmission of Rebind message for Prefix Delegation | 🟢 Passes | None |
| 1.2.7 | Transmission of Release messages for Prefix Delegation | 🟡 Partly. Release only on exit, as 1.1.13 | None |
| 1.2.8 | Reception of Advertise messages | ⌛ Not yet, as 1.1.15 | None |
| 1.2.9 | Reception of a Reply Message for Prefix Delegation | 🟡 Partly, as 1.1.16 | `TestApplyReply` |
| 1.2.10 | Receipt of Invalid Reply Messages for Prefix Delegation | 🟢 Passes | `TestClientValidation` |
| 1.3.1 | On-link Determination | 🐧 Kernel | None |
| 1.3.2 | Prefix Information Option Processing, On-link Flag | 🟡 Partly. A /64 not shared with the LAN is on-link through the SLAAC address in it, so one without the A flag gets no on-link route | None |
| 1.3.3 | Host Prefix List | 🟡 Partly, as 1.3.2 | None |
| 1.3.4 | Neighbor Solicitation Origination, Address Resolution | 🐧 Kernel | None |
| 1.3.5 | Neighbor Solicitation Processing, IsRouterFlag | 🐧 Kernel | None |
| 1.3.6 | Neighbor Advertisement Processing, R-bit Change | 🐧 Kernel | None |
| 1.3.7 | Router Solicitation | 🟢 Passes | None |
| 1.3.8 | Router Solicitations, Solicited Router Advertisement | 🟢 Passes | `TestRSValidation` |
| 1.3.9 | Host Ignores Router Solicitations | 🐧 Kernel | None |
| 1.3.10 | Default Router Switch | 🟡 Partly. Routers coexist, each with a route of its own, but one that stops answering before its lifetime ends is not avoided | `TestRouterMetrics` |
| 1.3.11 | Router Advertisement Processing, Validity | 🔵 Likely passes | None |
| 1.3.12 | Router Advertisement Processing, Cur Hop Limit | 🟢 Passes | None |
| 1.3.13 | Router Advertisement Processing, Router Lifetime | 🔵 Likely passes | `TestRouterMetrics` |
| 1.3.14 | Router Advertisement Processing, Reachable Time | 🟢 Passes | None |
| 1.3.15 | Router Advertisement Processing, Neighbor Cache | 🐧 Kernel | None |
| 1.3.16 | Router Advertisement Processing, IsRouter flag | 🐧 Kernel | None |
| 1.3.17 | Next-hop Determination | 🟢 Passes | None |
| 1.3.18 | Router Advertisement Processing, On-link determination | 🟢 Passes | `TestParseRAPrefixes` |
| 1.3.19 | Unrecognized – End Node | 🐧 Kernel | None |
| 1.3.20 | Unrecognized Routing Type – Intermediate Node | 🐧 Kernel | None |
| 1.4.1 | Address Autoconfiguration and Duplicate Address Detection | 🐧 Kernel | None |
| 1.4.2 | Receiving DAD Neighbor Solicitations and Advertisements | 🐧 Kernel | None |
| 1.4.3 | Validation of DAD Neighbor Solicitations | 🐧 Kernel | None |
| 1.4.4 | Validation of DAD Neighbor Advertisements | 🐧 Kernel | None |
| 1.4.5 | Receiving Neighbor Solicitations for Address Resolution | 🐧 Kernel | None |
| 1.4.6 | Global Address Autoconfiguration and DAD | 🔵 Likely passes | None |
| 1.4.7 | Address Lifetime Expiry | 🔵 Likely passes | None |
| 1.4.8 | Multiple Prefixes and Network Renumbering | 🟢 Passes | `TestMergePIOs` |
| 1.4.9 | Prefix-Information Option Processing | 🟢 Passes | `TestParseRAPrefixes` |
| 1.4.10 | Prefix-Information Option Processing, Lifetime | 🟢 Passes | `TestMergePIOs` |
| 1.5.1 | Confirm Ping | 🐧 Kernel | None |
| 1.5.2 | Stored PMTU | 🐧 Kernel | None |
| 1.5.3 | Non-zero ICMPv6 Code | 🐧 Kernel | None |
| 1.5.4 | Reduces PMTU On-link | 🐧 Kernel | None |
| 1.5.5 | Reduces PMTU Off-link | 🐧 Kernel | None |
| 1.5.6 | Receiving MTU Below IPv6 Minimum Link MTU | 🐧 Kernel | None |
| 1.5.7 | Increase Estimate | 🐧 Kernel | None |
| 1.5.8 | Router Advertisement with MTU Option | 🟢 Passes | `TestParseRAOptions`, `TestParseRAMTUBounds` |
| 1.5.9 | Checking For Increase in PMTU | 🐧 Kernel | None |
| 1.6.1 | Router Solicitation Transmission | 🟢 Passes | None |
| 1.6.2 | L Flag Processing | 🟢 Passes | `TestWANAddressOffLink` |
| 1.6.3 | Reconfigure Message | 🟢 Passes | `TestReconfigureAuth`, `TestReconfigureRoundTrip` |
| 1.6.4 | M Flag Processing | 🟢 Passes | `TestDHCPv6ClientStartsOnTheRAAgainstKernel` |
| 1.6.5 | Prefix Delegation Size | 🟢 Passes | `TestPDHintRetry` |
| 1.6.6 | M and O Flag for Prefix Delegation | 🟢 Passes | `TestDHCPv6ClientStartsOnTheRAAgainstKernel` |
| 1.6.7 | Dynamic Routing Protocol | 🟢 Passes | None |
| 2.1.1 | Basic Message Exchange | 🔵 Likely passes | `TestServerSolicitRequestCommit` |
| 2.1.2 | Transaction ID Consistency | 🔵 Likely passes | None |
| 2.1.3 | Implementation of DHCP Constants | 🔵 Likely passes | None |
| 2.1.4 | Server Message Format | 🔵 Likely passes | None |
| 2.1.5 | DHCPv6 Option | 🙅 Deviates by design. An address off the link is returned with lifetime 0 next to a new one, as RFC 9096 asks, where the test wants NotOnLink | `TestServerRebindAfterPrefixChange` |
| 2.1.6 | DHCP Unique Identifier (DUID) Contents | 🔵 Likely passes | None |
| 2.1.7 | Transmission of Advertise Messages | 🟢 Passes | `TestServerSolicitRequestCommit` |
| 2.1.8 | Transmission of Reply Messages | 🔵 Likely passes | `TestServerSolicitRequestCommit` |
| 2.1.9 | Reception of Solicit Message | 🟢 Passes | `TestServerSolicitRequestCommit`, `TestServerRapidCommit` |
| 2.1.10 | Reception of Request Messages | 🟡 Partly. Unicast is answered with UseMulticast; an address off the link as 2.1.5 | `TestServerSolicitRequestCommit`, `TestServerValidation` |
| 2.1.11 | Reception of Confirm Messages | 🟢 Passes | `TestServerConfirm` |
| 2.1.12 | Reception of Renew Messages | 🟢 Passes | `TestServerRenewWithoutBinding` |
| 2.1.13 | Reception of Rebind Messages | 🔵 Likely passes | `TestServerRebindAfterPrefixChange` |
| 2.1.14 | Reception of Release Messages | 🟢 Passes | `TestServerReleaseAndServerIDCheck`, `TestServerValidation` |
| 2.1.15 | Reception of Decline Messages | 🟢 Passes | `TestServerKeepsDeclinedAddressOut` |
| 2.1.16 | Reception of Invalid Solicit Message | 🟢 Passes | `TestServerValidation` |
| 2.1.17 | Reception of Invalid Request Message | 🟢 Passes | None |
| 2.1.18 | Reception of Invalid Confirm Message | 🟢 Passes | `TestServerValidation` |
| 2.1.19 | Reception of Invalid Renew Message | 🟢 Passes | None |
| 2.1.20 | Reception of Invalid Rebind Message | 🟢 Passes | `TestServerValidation` |
| 2.1.21 | Reception of Invalid Release Message | 🟢 Passes | `TestServerReleaseAndServerIDCheck` |
| 2.1.22 | Reception of Invalid Decline Messages | 🟢 Passes | None |
| 2.1.23 | Server Message Validation | 🟢 Passes | `TestServerValidation` |
| 2.2.1 | Basic Message Exchange | 🟢 Passes | `TestServerInformationRequest` |
| 2.2.2 | Transaction ID Consistency | 🟢 Passes | None |
| 2.2.3 | Implementation of DHCP constants | 🟢 Passes | None |
| 2.2.4 | Server Message Format | 🟢 Passes | None |
| 2.2.5 | DHCP Options | 🟢 Passes | None |
| 2.2.6 | DHCP Unique Identifier (DUID) Contents | 🟢 Passes | None |
| 2.2.7 | Creation and Transmission of Reply Messages | 🟢 Passes | `TestServerInformationRequest` |
| 2.2.8 | Reception of Invalid Information-request message | 🟢 Passes | `TestServerValidation` |
| 2.2.9 | Server Message Validation | 🟢 Passes | `TestServerValidation` |
| 2.3.1 | Version Field | 🐧 Kernel | None |
| 2.3.2 | Flow Label Non-Zero | 🐧 Kernel | None |
| 2.3.3 | Payload Length | 🐧 Kernel | None |
| 2.3.4 | No Next Header after IPv6 Header | 🐧 Kernel | None |
| 2.3.5 | Hop Limit Zero – End Node | 🐧 Kernel | None |
| 2.3.6 | No Next Header after Extension Header | 🐧 Kernel | None |
| 2.3.7 | Extension Header Processing Order | 🐧 Kernel | None |
| 2.3.8 | Option Processing Order | 🐧 Kernel | None |
| 2.3.9 | Options Processing, Hop-by-Hop Options Header – End Node | 🐧 Kernel | None |
| 2.3.10 | Options Processing, Destination Options Header | 🐧 Kernel | None |
| 2.3.11 | Fragment Reassembly | 🐧 Kernel | None |
| 2.3.12 | Reassembly Time Exceeded | 🐧 Kernel | None |
| 2.3.13 | Stub Fragment Header | 🐧 Kernel | None |
| 2.4.1 | On-link Determination | 🐧 Kernel | None |
| 2.4.2 | Resolution Wait Queue | 🐧 Kernel | None |
| 2.4.3 | Neighbor Solicitation Origination, Address Resolution | 🐧 Kernel | None |
| 2.4.4 | Neighbor Solicitation Origination, Reachability Confirmation | 🐧 Kernel | None |
| 2.4.5 | Invalid Neighbor Solicitation Handling | 🐧 Kernel | None |
| 2.4.6 | Neighbor Solicitation Processing, NCE State INCOMPLETE | 🐧 Kernel | None |
| 2.4.7 | Neighbor Solicitation Processing, NCE State REACHABLE | 🐧 Kernel | None |
| 2.4.8 | Neighbor Solicitation Processing, NCE State STALE | 🐧 Kernel | None |
| 2.4.9 | Neighbor Solicitation Processing, NCE State PROBE | 🐧 Kernel | None |
| 2.4.10 | Invalid Neighbor Advertisement Handling | 🐧 Kernel | None |
| 2.4.11 | Neighbor Advertisement Processing, NCE State INCOMPLETE | 🐧 Kernel | None |
| 2.4.12 | Neighbor Advertisement Processing, NCE State REACHABLE | 🐧 Kernel | None |
| 2.4.13 | Neighbor Advertisement Processing, NCE State STALE | 🐧 Kernel | None |
| 2.4.14 | Neighbor Advertisement Processing, NCE State PROBE | 🐧 Kernel | None |
| 2.4.15 | Router Ignores Invalid Router Solicitations | 🟢 Passes | `TestRSValidation` |
| 2.4.16 | Router Sends Valid Router Advertisement | 🟢 Passes | None |
| 2.4.17 | Processing Router Solicitations | 🟢 Passes | `TestRAServerAnswersRSAgainstKernel` |
| 2.5.1 | Address Autoconfiguration and Duplicate Address Detection | 🐧 Kernel | None |
| 2.5.2 | Receiving DAD Neighbor Solicitations and Advertisements | 🐧 Kernel | None |
| 2.5.3 | Validation of DAD Neighbor Solicitations | 🐧 Kernel | None |
| 2.5.4 | Validation of DAD Neighbor Advertisements | 🐧 Kernel | None |
| 2.5.5 | Receiving Neighbor Solicitations for Address Resolution | 🐧 Kernel | None |
| 2.5.6 | Global Address Autoconfiguration and DAD | 🐧 Kernel | None |
| 2.6.1 | Replying to Echo Request | 🐧 Kernel | None |
| 2.6.2 | Unrecognized Next Header (Parameter Problem Generation) | 🐧 Kernel | None |
| 2.6.3 | Unknown Informational Message Type | 🐧 Kernel | None |
| 2.6.4 | Error Condition With Multicast Destination | 🐧 Kernel | None |
| 2.6.5 | Error Condition With Non-Unique Source - Unspecified | 🐧 Kernel | None |
| 2.6.6 | Error Condition With Non-Unique Source - Multicast | 🐧 Kernel | None |
| 2.6.7 | Error Condition With Non-Unique Source - Anycast | 🐧 Kernel | None |
| 2.7.1 | Assigning Prefixes to LAN Interfaces | 🟢 Passes | `TestSplitLAN`, `TestStoreLifecycle` |
| 2.7.2 | Route Information Option | 🟢 Passes | `TestRAAdvertisesTheDelegationAndULA`, `TestRAAdvertisesADelegated64` |
| 2.7.3 | No Prefixes Delegated | 🟡 Partly, by design. With no delegation, the /64 of the upstream RA is shared with the LAN as RFC 7278 describes, so the router is a default router (part A); parts B and C pass | `TestRABuildNoPrefixNoUpstream` |
| 2.7.4 | DNS Information in Router Advertisement | 🟢 Passes | `TestRABuildPrefixAndDNS`, `TestRABuildOverridesAndExtras` |
| 2.7.5 | Prefix Change | 🟢 Passes | `TestRABuildDeprecatedPrefix`, `TestRAWithdrawsStalePrefixes`, `TestStoreLifecycle` |
| 2.7.6 | Unknown Prefix | 🟢 Passes | `TestFirewallBorderAgainstKernel` |
| 2.7.7 | Unique Local Address Prefix | 🟢 Passes | `TestStoreULA`, `TestRAAdvertisesTheDelegationAndULA` |
| 3.1.1 | IP Forwarding – Source and Destination Address | 🐧 Kernel | None |
| 3.1.2 | Flow Label Non-Zero | 🐧 Kernel | None |
| 3.1.3 | Payload Length | 🐧 Kernel | None |
| 3.1.4 | No Next Header After IPv6 Header | 🐧 Kernel | None |
| 3.1.5 | Hop Limit Decrement | 🐧 Kernel | None |
| 3.1.6 | No Next Header after Extension Header | 🐧 Kernel | None |
| 3.1.7 | Options Processing Hop-by-Hop Options Header | 🐧 Kernel | None |
| 3.1.8 | Packet Too Big Message Generation | 🐧 Kernel | None |
| 3.1.9 | Hop Limit Exceeded (Time Exceeded Generation) | 🐧 Kernel | None |
| 3.1.10 | Error Condition With ICMPv6 Error Message | 🐧 Kernel | None |
| 3.2.1 | IPv6 Forwarding before Address Acquisition | 🟢 Passes | `TestFirewallBorderAgainstKernel` |
| 3.2.2 | No Default Route | 🟢 Passes | `TestRARouterLifetime` |
| 3.2.3 | Forwarding Loops | 🟢 Passes | `TestRouteUnreachableAgainstKernel` |
| 3.2.4 | Unique Local Address Forwarding | 🟢 Passes | `TestFirewallBorderAgainstKernel`, `TestFirewallSourceFilterOffAgainstKernel` |

## The WAN side

- **RFC 8415, DHCPv6.** The client follows its retransmission rules, authenticates Reconfigure
  with the key it was given (§20.4) and, only when `-dhcp6c-release` asks, releases on exit.
- **RFC 4861 and RFC 4862, Neighbor Discovery and SLAAC.** The RA on the WAN is read as a host
  reads it. The RA MTU sets the link's IPv6 MTU, not the interface MTU (§6.3.4).
- **RFC 7217, stable interface identifiers.** Addresses sixup configures are stable per network
  and unlinkable across networks, from a secret kept in the state directory, unless
  `-wan-iid` or `-lan-iid` fixes them.
- **RFC 8981, temporary addresses.** `-tempaddr` adds rotating WAN addresses for the
  router's own traffic, in the first LAN's delegated /64 when there is one, so that the upstream
  router keeps no neighbor entry for each. The kernel does not accept the temporary flag from userspace, so RFC 6724
  rule 7 never applies; the newest address is the source instead, and a rotation follows every new
  static address.
- **RFC 9131, announcing new addresses.** A new WAN address is announced to the upstream routers
  with unsolicited Neighbor Advertisements, so the first packets towards it are not lost.

## The LAN side

- **RFC 4861, router advertisements.** Intervals, the burst after a change and the delay on
  answering RS follow the RFC.
- **RFC 4191, Route Information.** The delegated prefixes and the ULA are advertised as routes,
  along with those given with `-ra-route`.
- **RFC 8106, DNS in the RA.** RDNSS and DNSSL carry a lifetime of 3 × MaxRtrAdvInterval by
  default, cut to what is left of the upstream prefix.
- **RFC 8415, the DHCPv6 server.** Stateful with IA_NA, or stateless, and delegating prefixes to
  downstream routers. When the prefix changes, clients with a Reconfigure key are told to renew.
- **RFC 8987, routes for delegated prefixes.** A delegated prefix is routed to the router it went
  to for as long as the delegation lasts, as that RFC asks of a delegating relay.
- **RFC 4193, ULA.** `-ula auto` generates a random /48 and keeps it.
- **RFC 7278, sharing a /64.** When the line gives only a /64, it moves to the LAN, and on an
  Ethernet WAN sixup answers Neighbor Discovery for the LAN hosts there, in the manner of the
  proxy of RFC 4389.

## Unsolicited traffic

### RFC 6092, Simple Security in Customer Premises Equipment

The IPv6 filter a home router applies to traffic from the Internet. It is the default with
`-unsolicited request`.

| ID | What it asks | sixup | Tested by |
|---|---|---|---|
| REC-1 | Forward nothing with a multicast source (MUST NOT) | 🐧 Kernel | None |
| REC-2 | Forward no multicast within the scope boundary, organization-local by default (MUST NOT) | 🐧 Kernel. sixup routes no multicast | None |
| REC-3 | Forward no addresses forbidden on the Internet, such as site-local and IPv4-mapped (MUST NOT) | 🟡 Partly. LAN sources and WAN destinations outside the LAN prefixes are dropped; a forbidden WAN source or LAN destination is not checked | `TestFirewallBorderAgainstKernel` |
| REC-4 | Forward no deprecated extension headers, and never routing header type 0 (SHOULD NOT, MUST NOT) | 🐧 Kernel. Linux drops routing header type 0 | None |
| REC-5 | Forward nothing out whose source is not an interior prefix (MUST NOT) | 🟢 Done, unless `-source-filter=false` | `TestFirewallBorderAgainstKernel`, `TestFirewallSourceFilterOffAgainstKernel` |
| REC-6 | Forward nothing in whose source is an interior prefix (MUST NOT) | 🟢 Done, in every `-unsolicited` mode. A /64 shared with the WAN link is left out, as the WAN side has hosts in it too | `TestFirewallBorderAgainstKernel` |
| REC-7 | Forward no ULA to or from the exterior by default (SHOULD NOT) | 🟢 Done, except the ULA the upstream advertises, as ULA-4 | `TestFirewallBorderAgainstKernel`, `TestFirewallSourceFilterOffAgainstKernel`, `TestRAClientReportsUpstreamULA` |
| REC-8 | Answer no DNS queries from the exterior by default (MUST NOT) | ➖ Not applicable. sixup has no resolver | None |
| REC-9 | Serve no DHCPv6 on the exterior (MUST NOT) | 🟢 Done. The server listens on the LAN interfaces only | None |
| REC-10 | Forward no ICMPv6 errors that match no flow (SHOULD NOT) | 🟢 Done, conntrack marks them invalid | `TestFirewallICMPv6AgainstKernel` |
| REC-11 | Endpoint independent filtering for other transports by default (SHOULD) | 🟡 Partly. UDP and TCP only; other transports are filtered by address | `TestFirewallAgainstKernel`, `TestFirewallICMPv6AgainstKernel` |
| REC-12 | State for other transports kept at least 2 minutes idle, 5 by default (MUST NOT) | 🐧 Kernel. The conntrack default is 10 minutes | None |
| REC-13 | A convenient and secure way to update the firmware (SHOULD) | ➖ Not applicable. sixup is updated with the distribution's packages | None |
| REC-14 | UDP state kept at least 2 minutes idle, 5 by default (MUST NOT) | 🟢 Done, as an endpoint stays reachable for 5 minutes after it last sent | None |
| REC-15 | UDP state on well-known ports may expire sooner (MAY) | ➖ Not applicable, a permission | None |
| REC-16 | UDP state refreshed by outbound packets (MUST) | 🟢 Done | None |
| REC-17 | Endpoint independent filtering for UDP by default (SHOULD) | 🟢 Done | `TestFirewallAgainstKernel` |
| REC-18 | ICMPv6 errors for a forwarded UDP flow forwarded too (MUST) | 🟢 Done, as related traffic | `TestFirewallICMPv6AgainstKernel` |
| REC-19 | No ICMPv6 message ends UDP state (MUST NOT) | 🐧 Kernel | None |
| REC-20 | UDP-Lite handled as UDP, but apart from it (SHOULD) | 🟡 Partly. Flows the LAN starts pass; there is no endpoint independent filtering for it | None |
| REC-21 | AH not blocked in the default mode (MUST NOT) | 🟢 Done | `TestFirewallAgainstKernel` |
| REC-22 | ESP not blocked in the default mode (MUST NOT) | 🟢 Done | `TestFirewallAgainstKernel` |
| REC-23 | ICMPv6 errors for a forwarded ESP flow forwarded too (MUST) | 🟢 Done, as related traffic | None |
| REC-24 | IKE, UDP port 500, not blocked in the default mode (MUST NOT) | 🟢 Done | `TestFirewallAgainstKernel` |
| REC-25 | ESP state indexed by the two addresses and the protocol, not the SPI (SHOULD) | 🐧 Kernel. conntrack tracks ESP by address and protocol | None |
| REC-26 | HIP not blocked in the default mode (MUST NOT) | 🟢 Done | `TestFirewallAgainstKernel` |
| REC-27 | Mobile IPv6 type 2 routing headers matching a flow not blocked (MUST NOT) | 🐧 Kernel, through conntrack; not tested here | None |
| REC-28 | Mobility Header flows forwarded out, and in when permitted (MUST) | 🐧 Kernel, through conntrack; not tested here | None |
| REC-29 | The tunnel of a forwarded Mobility Header flow forwarded both ways (MUST) | 🐧 Kernel, through conntrack; not tested here | None |
| REC-30 | ICMPv6 errors for a forwarded Mobility Header flow forwarded too (MUST) | 🐧 Kernel, through conntrack; not tested here | None |
| REC-31 | All valid TCP sequences, simultaneous open included (MUST) | 🟢 Done | `TestFirewallICMPv6AgainstKernel` |
| REC-32 | The TCP window not enforced when the window scale was not seen (MUST NOT) | 🐧 Kernel. conntrack is liberal with a flow it picked up midway | None |
| REC-33 | Endpoint independent filtering for TCP by default (SHOULD) | 🟢 Done | `TestFirewallICMPv6AgainstKernel` |
| REC-34 | Answer an unsolicited SYN with ICMPv6 code 1 after 6 seconds (MUST) | 🟢 Done. The firewall hands the SYNs it drops to sixup through NFLOG, at most 50 a second; after 6 seconds sixup answers, unless conntrack shows the LAN host opened the connection meanwhile, a simultaneous open the answer would abort | `TestFirewallRejectsSYNAgainstKernel` |
| REC-35 | TCP state kept at least 2 h 4 min when established, 4 min when transitory (MUST NOT) | 🟡 Partly. Kernel defaults: 5 days established, but some transitory states such as SYN_SENT last 2 minutes | None |
| REC-36 | ICMPv6 errors for a forwarded TCP flow forwarded too (MUST) | 🟢 Done, as related traffic | `TestFirewallICMPv6AgainstKernel` |
| REC-37 | No ICMPv6 message ends TCP state (MUST NOT) | 🐧 Kernel | None |
| REC-38 | All valid SCTP sequences, simultaneous open included (MUST) | 🐧 Kernel, through conntrack; not tested here | None |
| REC-39 | Answer an unsolicited SCTP INIT with ICMPv6 code 1 after 6 seconds (MUST) | ⌛ Not yet. The INIT is dropped; the answer of REC-34 covers TCP only | None |
| REC-40 | SCTP state kept at least 2 h 4 min when established (MUST NOT) | 🐧 Kernel, through conntrack; not tested here | None |
| REC-41 | ICMPv6 errors for a forwarded SCTP association forwarded too (MUST) | 🐧 Kernel, through conntrack; not tested here | None |
| REC-42 | No ICMPv6 message ends SCTP state (MUST NOT) | 🐧 Kernel | None |
| REC-43 | DCCP flows out, and in for permitted service codes (MUST) | 🟡 Partly. Flows the LAN starts pass through conntrack; no service code can be opened | None |
| REC-44 | DCCP state kept at least 2 h 4 min when open, 8 min when transitory (MUST NOT) | 🐧 Kernel, through conntrack; not tested here | None |
| REC-45 | ICMPv6 errors for a forwarded DCCP flow forwarded too (MUST) | 🐧 Kernel, through conntrack; not tested here | None |
| REC-46 | No ICMPv6 message ends DCCP state (MUST NOT) | 🐧 Kernel | None |
| REC-47 | Shim6 flows forwarded out, and in when permitted (MUST) | 🐧 Kernel, through conntrack; not tested here | None |
| REC-48 | A protocol for programs to ask for inbound traffic (SHOULD) | 🟢 Done with PCP | `TestPCPPinholes`, `TestFirewallAgainstKernel` |
| REC-49 | A transparent mode, easy to select, and allowed as the default (MUST, MAY) | 🟢 Done, `-unsolicited allow` | `TestFirewallBorderAgainstKernel` |
| REC-50 | Offer no management service to the exterior by default (MUST NOT) | 🟢 Done. sixup has no management service, and PCP and DHCPv6 answer on the LAN only | None |

Why `request` is the default is explained in [Recipes](recipes.md#reaching-lan-hosts-from-the-internet).
The filter covers traffic forwarded to the LAN only, and leaves a prefix delegated to a
downstream router to that router's own filter.

### RFC 4890, ICMPv6 filtering

Section 4.3 of the RFC sorts the ICMPv6 that crosses a firewall. The sixup column is for
traffic from the WAN to the LAN under `-unsolicited request` and `deny`; the LAN sends out any
ICMPv6, and `allow` lets it all in.

| Section | Message | What it asks | sixup | Tested by |
|---|---|---|---|---|
| 4.3.1 | Destination Unreachable (1), all codes | Must not be dropped | 🟢 Let through | `TestFirewallICMPv6AgainstKernel` |
| 4.3.1 | Packet Too Big (2) | Must not be dropped | 🟢 Let through | `TestFirewallICMPv6AgainstKernel` |
| 4.3.1 | Time Exceeded (3), code 0 | Must not be dropped | 🟢 Let through | `TestFirewallICMPv6AgainstKernel` |
| 4.3.1 | Parameter Problem (4), codes 1 and 2 | Must not be dropped | 🟢 Let through | `TestFirewallICMPv6AgainstKernel` |
| 4.3.1 | Echo Request (128) | Must not be dropped | 🟢 Let through | `TestFirewallAgainstKernel`, `TestFirewallICMPv6AgainstKernel` |
| 4.3.1 | Echo Reply (129) | Must not be dropped | 🟢 Let through as the answer to an Echo Request from the LAN | `TestFirewallICMPv6AgainstKernel` |
| 4.3.2 | Time Exceeded (3), code 1 | Normally not dropped | 🟢 Let through | `TestFirewallICMPv6AgainstKernel` |
| 4.3.2 | Parameter Problem (4), code 0 | Normally not dropped | 🟢 Let through | `TestFirewallICMPv6AgainstKernel` |
| 4.3.2 | Mobile IPv6 Home Agent Address Discovery and Mobile Prefix (144 to 147) | Normally not dropped | 🔴 Not done. Dropped, answers to the LAN included, since conntrack does not pair these | `TestFirewallICMPv6AgainstKernel` |
| 4.3.3 | Neighbor Discovery, MLD, SEND and Multicast Router Discovery (130 to 137, 141 to 143, 148, 149, 151 to 153) | Dropped anyway | 🐧 Kernel. Link-local, never forwarded | None |
| 4.3.4 | Seamoby Experimental (150) | A policy to define | 🟢 Dropped | `TestFirewallICMPv6AgainstKernel` |
| 4.3.4 | Unallocated error messages (5 to 99, 102 to 126) | A policy to define | 🟢 Dropped | `TestFirewallICMPv6AgainstKernel` |
| 4.3.4 | Unallocated informational messages (154 to 199, 202 to 254) | A policy to define | 🟢 Dropped | `TestFirewallICMPv6AgainstKernel` |
| 4.3.5 | Node Information (139, 140) | Dropped unless a good case is made | 🟢 Dropped, except the answer to a query from the LAN | `TestFirewallICMPv6AgainstKernel` |
| 4.3.5 | Router Renumbering (138) | Dropped unless a good case is made | 🟢 Dropped | `TestFirewallICMPv6AgainstKernel` |
| 4.3.5 | Experimental (100, 101, 200, 201) | Dropped unless a good case is made | 🟢 Dropped | `TestFirewallICMPv6AgainstKernel` |
| 4.3.5 | Extension (127, 255) | Dropped unless a good case is made | 🟢 Dropped | `TestFirewallICMPv6AgainstKernel` |

### RFC 6887, Port Control Protocol

The PCP server on UDP 5351 of each LAN answers MAP and announces restarts with ANNOUNCE. Over
IPv6 a mapping opens a pinhole in the filter; over IPv4 it forwards a port of the tunnel's
address. Lifetimes are kept between 120 seconds and 24 hours, errors carry the lifetimes the RFC
gives, the nonce of an existing mapping is checked, and PREFER_FAILURE is honoured. PEER and
THIRD_PARTY are not supported, and a host holds at most 16 mappings.

### RFC 6886, NAT Port Mapping Protocol

NAT-PMP, which PCP replaced, is answered on the same port for the programs that still know only
it, such as some BitTorrent clients. It is IPv4 only. A mapping request is handled as PCP's MAP
and shares its mappings, as RFC 6887 appendix A allows; the external address is the tunnel's, and
it is announced to 224.0.0.1 port 5350 ten times after a start or a change, as section 3.2.1
asks. A mapping made by PCP cannot be renewed or deleted by NAT-PMP, which carries no nonce.
Tested by `TestNATPMP` and `TestPCPServerAgainstKernel`.

## IPv4 over IPv6

- **RFC 6333 and RFC 6334, DS-Lite.** The AFTR name comes from DHCPv6 option 64 and is resolved
  through the DNS servers the line hands out, since the system's resolver may be reachable only
  through the tunnel that name is for. The B4 uses
  192.0.0.2, and the AFTR translates, so sixup adds no NAT.
- **RFC 7597 and RFC 7598, MAP-E.** Rules come from the DHCPv6 options or, for the Japanese
  providers that send none, from built-in tables. The CE address takes the §6 form, and source
  ports are kept inside the line's port set by a port restricted NAT, as a MAP-E CE must.
- **RFC 6052, NAT64 prefixes.** The well-known `64:ff9b::/96` by default, or a network specific
  prefix with `-nat64-prefix`.
- **RFC 6146, stateful NAT64.** Done by Jool with `-nat64 jool`.
- **RFC 8781, PREF64 in the RA.** Advertised while the NAT64 translates, with a lifetime of
  3 × MaxRtrAdvInterval, and withdrawn with lifetime 0.
- **RFC 6877, 464XLAT.** The CLAT is on the clients; PREF64 is what lets them find the prefix.
- **RFC 8925, IPv6-Only Preferred.** A DHCPv4 option, left to the DHCPv4 server, since sixup runs
  none.

## Beyond the RFCs

Other documents also set requirements for home routers. The ones below were checked against the
publisher's own page in September 2026. They have not been checked item by item against sixup,
except where a line says so.

### IETF

- **[draft-ietf-v6ops-rfc7084bis](https://datatracker.ietf.org/doc/draft-ietf-v6ops-rfc7084bis/)**,
  revision 06 of July 2026, an active v6ops draft meant to replace RFC 7084 as a BCP. It adds
  LAN-side prefix delegation (RFC 9818) and the renumbering rules of RFC 9096, drops 6rd and
  DS-Lite, and turns BCP 38 filtering on by default. It is the likely next baseline for sixup.
- **[draft-ietf-v6ops-prefix-to-end-sites](https://datatracker.ietf.org/doc/draft-ietf-v6ops-prefix-to-end-sites/)**,
  April 2026. It asks ISPs for a /48, at least a /56 and a prefix that stays the same, and calls
  a single /64 harmful.
- **[BCP 38](https://www.rfc-editor.org/info/bcp38)** (RFC 2827), ingress filtering, which
  RFC 7084 S-2 asks for and sixup does not do yet.
- Newer RFCs on CE routers, not yet reviewed here:
  [RFC 9818](https://www.rfc-editor.org/info/rfc9818/) on prefix delegation inside the LAN, and
  [RFC 9762](https://www.rfc-editor.org/info/rfc9762/) on the RA flag that points hosts to
  DHCPv6-PD.

### Broadband Forum

- **[TR-124 Issue 9](https://www.broadband-forum.org/pdfs/tr-124-9-0-0.pdf)** (2024), the
  industry's requirements for a residential gateway, in modules an ISP picks from. Its IPv6
  modules ask for DS-Lite and MAP-E, a ULA, RFC 6092 filtering and a PCP client on the WAN.
  LAN.PFWDv6.4 says not to filter prefixes delegated to routers in the LAN, which is what sixup
  does.
- **[TR-187](https://www.broadband-forum.org/pdfs/tr-187-2-0-0.pdf)** (2013), IPv6 over PPP, and
  **[TR-177](https://www.broadband-forum.org/pdfs/tr-177-1-0-1.pdf)** (2017), IPv6 over Ethernet
  access. They describe the lines sixup meets as a PPPoE or IPoE WAN.
- TR-069, TR-369 and the TR-181 data model are for remote management by the ISP, which sixup does
  not do.

### RIPE

- **[RIPE-690](https://www.ripe.net/publications/docs/ripe-690/)** (2017), prefix assignment to
  end users. A /48, or a /56 for homes, that stays the same, handed out with DHCPv6-PD. This is
  why sixup asks for a /56 and warns when a line gives only a /64.
- **[RIPE-772](https://www.ripe.net/publications/docs/ripe-772/)** (2021), IPv6 requirements for
  buying ICT equipment, replacing RIPE-554. For CPE it makes RFC 7084 and RFC 6092 mandatory, and
  asks that the device works on IPv6 alone with IPv6 on by default.

### Test and certification

- **[IPv6 Ready Logo, CE Router](https://www.ipv6ready.org/resources/cpe.html)**, the conformance
  tests of the IPv6 Forum and UNH-IOL. They follow RFC 7084 and the DHCPv6 and ND RFCs, and do not
  test RFC 6092 or the IPv4 transition tunnels. See [IPv6 Ready CE Router tests](#ipv6-ready-ce-router-tests)
  for how sixup stands.
- **[USGv6](https://nvlpubs.nist.gov/nistpubs/specialpublications/NIST.SP.500-267Br1.pdf)**
  (NIST SP 500-267B Rev 1, 2020), the US government profile. Its optional CE-Router capability
  means RFC 7084, BCP 38 and RFC 6092.

### Cable networks

- **[CableLabs eRouter](https://account.cablelabs.com/server/alfresco/6ee2a604-d342-47bf-bd32-f6cd3ea72d1d)**
  (CM-SP-eRouter-I22, 2024). It asks for DHCPv6-PD to every LAN interface, a DUID that stays the
  same, MAP-E, MAP-T and DS-Lite, and a stateful firewall on by default. It also sorts the
  recommendations of RFC 6092 into critical, best practice and not required.

### Japan

- **[NTT East, IP通信網サービスのインタフェース 第三分冊](https://flets.com/pdf/ip-int-3.pdf)**
  (edition 46, 2026). How the FLET'S lines behave. On 光ネクスト IPoE the network sends an RA
  with a /64 and may offer DHCPv6-PD, with no IA_NA, and the prefix may change. 光クロス and 光25G
  delegate a /56. These are the conditions sixup is built for on Japanese lines.
- **[IPv6 家庭用ルータガイドライン 第3.0版](https://www.jaipa.or.jp/guideline/pdf/v6hgw_Guideline_3.0.pdf)**
  (IPv6 Promotion Council of Japan, 2024). Getting the prefix by DHCPv6-PD and accepting anything
  from /48 to /64, following prefix changes, RDNSS, a ULA, DS-Lite and MAP-E, and filtering in
  the manner of RFC 6092.
- **[v6プラス対応製品開発ガイド](https://www.jpix.ad.jp/files/developer_guide_v6plus_v1.3.pdf)**
  (JPIX, 2023). An overview only. The MAP-E rules of v6plus are given to vendors under NDA, so
  there is no public document to cite for the rule tables sixup carries.
- **[総務省 IPv6 研究会 第四次報告書](https://www.soumu.go.jp/main_content/000512977.pdf)**
  (Ministry of Internal Affairs and Communications, 2016). In 2015 only 41% of the home routers
  that members of CIAJ, the Japanese equipment makers' association, had on sale supported IPv6,
  and none of them had the IPv6 Ready Logo. The report asks vendors to support IPv6
  over PPPoE and IPoE and IPv4 over IPv6, with all of it on by default.

### China

The government sets the direction by policy, which is binding for operators and for the type
approval of devices. The industry and national standards are voluntary, and their text is not
free to read, so what they ask about IPv6 is not summarized here.

- **[推进互联网协议第六版（IPv6）规模部署行动计划](https://www.gov.cn/zhengce/2017-11/26/content_5242389.htm)**
  (2017). The national plan. New network equipment and terminals support IPv6.
- **[关于开展2019年IPv6网络就绪专项行动的通知](https://www.miit.gov.cn/jgsj/txs/wjfb/art/2020/art_ed97eb9802da4f168acb823227663f1b.html)**
  (MIIT, 2019). New home gateways support IPv6, dual stack by default, and give IPv6 addresses to
  the devices behind them.
- **[IPv6流量提升三年专项行动计划（2021-2023年）](https://www.cac.gov.cn/2021-07/09/c_1627415664435227.htm)**
  (MIIT and CAC, 2021). Devices that give out addresses turn IPv6 on by default and pass the
  prefix from the network on to the LAN.
- **[关于加快推进互联网协议第六版（IPv6）规模部署和应用工作的通知](https://www.gov.cn/zhengce/zhengceku/2021-07/23/content_5626963.htm)**
  (2021). New home wireless routers support IPv6 and have it on by default.
- **[工信部无〔2023〕174号](https://www.miit.gov.cn/jgsj/wgj/wjfb/art/2023/art_23dd3eaffc7e4e42a0c2e43b3415792a.html)**
  (MIIT, in force since December 2023). Binding. A wireless LAN device that gives out addresses
  needs IPv6, on by default, to get radio type approval. Its attachment, 无线局域网设备支持IPv6协议能力
  技术要求和测试方法, has three requirements. IPv6 is on by default, a bridge passes IPv6 through,
  and a router gives IPv6 addresses to its users and forwards their IPv6. The tests take the WAN
  over PPPoE, DHCPv4/v6 or a static address, and the LAN on SLAAC, SLAAC with RDNSS, or DHCPv6.
  They pass when a device fresh from power on has IPv6 without any setting, and its clients reach
  IPv4 and IPv6 sites. Nothing is asked about prefix delegation, prefix length or filtering.
- **[深化互联网协议第六版（IPv6）技术创新和融合应用实施方案（2026—2030年）](https://www.cac.gov.cn/2026-07/21/c_1786380789858394.htm)**
  (CAC, July 2026). New devices have IPv6 on by default, networks move away from NAT, and IPv6-only
  deployment begins.
- Voluntary standards, for reference.
  [GB/T 32403.1-2015](https://std.samr.gov.cn/gb/search/gbDetailed?id=71F772D80CF4D3A7E05397BE0A0AB82A)
  on home broadband gateways,
  [YD/T 3421.2-2019](https://std.samr.gov.cn/hb/search/stdHBDetailed?id=998D2858B47B98C7E05397BE0A0A95D8)
  on home smart gateways,
  [YD/T 7084—2026](https://std.samr.gov.cn/hb/search/stdHBDetailed?id=5A166B0E8B942BDAE06397BE0A0A0423)
  on IPv6 access over PPP, and
  [GB/T 46332-2025](https://std.samr.gov.cn/gb/search/gbDetailed?id=40B74A27FD85BD79E06397BE0A0AB048)
  on how ISPs assign IPv6 addresses.

### Elsewhere

- **[Brazil, ANATEL Ato nº 7971](https://informacoes.anatel.gov.br/legislacao/atos-de-certificacao-de-produtos/2023/1878-ato-7971)**
  (in force since 2024). Binding for certification. Fixed access CPE with routing has to meet
  RFC 7084, tested with the IPv6 Ready CE Router tests.
- **[Germany, BSI TR-03148](https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr03148/tr03148_node.html)**
  (Secure Broadband Router, 2023). Where the router has IPv6, it forwards no inbound IPv6 that
  belongs to no known connection, and it lists the ICMPv6 to let through.
