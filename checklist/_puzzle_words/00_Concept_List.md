## keyword and concept list

### IP and Network Discovery

`ip`, `ipv4`, `ipv6`, `private ip`, `public ip`, `reserved ip`, `martian address`, `anycast`, `unicast`, `multicast`, `broadcast`, `segment`, `vlan`, `trunk port`, `native vlan`, `tagged vlan`, `route reflector`, `stub network`, `supernet`, `supernetting`, `variable length subnet masking`, `vpc`, `subinterface`, `dual-stack network`, `overlay network`, `underlay network`, `ethernet frame`, `arp table`, `neighbour discovery`, `router advertisement`, `router solicitation`, `ndp snooping`, `icmp timestamp`, `icmp address mask request`, `icmp redirect`, `network flow`, `netflow`, `sflow`, `jflow`, `network tap`, `span port`, `traffic mirroring`, `promiscuous mode`, `sniffing`, `network map`, `as path`, `prefix list`, `route filter`, `prefix hijack`, `asn mapping`, `irt object`, `as-set`, `peeringdb attribute`, `bogon filter`, `radb record`, `irrdb`, `mpls label`, `mpls switching`, `bgp community`, `bogon prefixes`, `origin as`, `next hop`, `access-list`, `mac address block`, `oui lookup`, `lldp beacon`, `cdp broadcast`, `port mirroring`, `arp poisoning`, `arp flood`, `dhcp options`, `dhcp snooping`, `relay agent option`, `dhcp lease time`, `rogue dhcp server`, `directed broadcast`

***

### DNS, Namespace & Record Depth

`dns`, `tld`, `reserved tld`, `test tld`, `open tld`, `root zone`, `glue record`, `negative caching`, `nsec walking`, `nsec3`, `remembered record`, `hop-by-hop lookup`, `flapping record`, `dns view`, `split view`, `dns64`, `synthetic record`, `dns cookie`, `edns0`, `dnssec validation`, `unsigned delegation`, `trust anchor`, `insecure delegation`, `dns stapling`, `ocsp record`, `hinfo record`, `naptr record`, `wks record`, `dns compression`, `reverse map zone`, `wildcard label`, `extended label`, `cname at apex`, `synthetic aaaa`, `webfinger resource`, `key tag`, `ds digest`, `stand-alone ns`, `deep subdomain`, `record inheritance`, `shadow record`, `rogue secondary`, `misaligned ttl`, `dead record`, `forgotten host`, `parked resource`, `residual pointer`, `mailbox domain`, `mx chaining`, `unqualified name`, `unicode dns`, `punycode`, `idn variant`, `homoglyph domain`, `root hints`, `recursive timeout`, `unreachable server`, `authority section`, `additional section`, `edns client subnet`, `stealth name server`, `phantom cctld`, `algorithm downgrade`, `key size variation`, `extra rdata`, `zone walking`, `dns rebinding`, `cache snooping`, `transient wildcard`, `stale cache`, `overlapping delegation`

***

### Subdomain and Namespace Depth

`parent domain`, `root domain`, `second-level domain`, `third-level domain`, `deep nested subdomain`, `chained subdomains`, `split horizon domain`, `domain shadowing`, `multi-tenancy namespace`, `duplicated entry`, `legacy environment`, `orphaned subdomain`, `doppelganger domain`, `vanity domain`, `subdomain churn`, `fast flux subdomain`, `round-robin subdomain`, `subdomain footprint`, `staged asset`, `hidden endpoint`, `ephemeral subdomain`, `disposable hostname`, `regional prefix`, `geospecific label`, `language label`, `numeric label`, `nonstandard label`, `preprod namespace`, `qa environment`, `feature branch hostname`, `developer staging`, `sandbox host`, `audit domain`, `interop namespace`, `old logo domain`, `abandoned tenant`, `expired label`, `fallback pattern`, `internally exposed zone`, `external translation zone`, `region failover label`, `canary asset`, `blue/green testbed`

***

### Web/HTTP Layer and URL Profile

`url`, `uri`, `urn`, `absolute url`, `relative url`, `canonical url`, `url encoding`, `percent encoding`, `double encoding`, `utf-8 encoded`, `utf-16 variant`, `punycode transformation`, `host override`, `host normalization`, `trailing slash`, `double slash`, `triple slash`, `port in path`, `path normalization`, `symlink in path`, `directory traversal`, `unicode traversal`, `reserved character`, `rare delimiter`, `dotless domain`, `bare tld`, `local tld`, `webroot path`, `parent directory reference`, `malformed path`, `ambiguous extension`, `null byte injection`, `arbitrary resource`, `fragment identifier misuse`, `base path`, `mount point`, `multi-mount site`, `virtual host override`, `alternate port`, `endpoint alias`, `named route`, `subpath`, `shadow endpoint`, `private endpoint`, `preview endpoint`, `fingerprint path`, `endpoint versioning`, `legacy api`, `deprecated endpoint`, `country code switch`, `query string normalization`, `parameter alias`, `control parameter`, `reserved keyword`, `switch param`, `array param`, `nested object param`, `polymorphic param`, `structure variation`, `enum param`, `boolean flag`, `identifier param`, `hash param`, `timestamp param`, `temporal param`, `idempotency key`, `api version`, `correlator id`, `device id`, `switch field`, `hidden flag`, `private key param`

***

### HTTP/HTTPS, Service & Stack Enumeration

`protocol fingerprint`, `http version`, `method support`, `method override`, `custom method`, `uncommon method`, `proprietary method`, `extended header`, `legacy header`, `hop-by-hop header`, `x-forwarded-header chain`, `realip chain`, `cookie scope`, `max-age`, `expires syntax`, `domain scope`, `path scope`, `secure only`, `samesite mode`, `cookie attribute variation`, `default cookie`, `static cookie`, `load balancer cookie`, `affinity cookie`, `session cookie pattern`, `encoded cookie`, `base64 token`, `jwt existence`, `default bearer token`, `api key hint`, `referrer origin`, `referer typo`, `accept-charset`, `accept-encoding`, `accept-language`, `variant negotiation`, `web server banner`, `powered-by header`, `x-aspnet-version`, `default x-error`, `stack trace leakage`, `debug message`, `unhandled exception`, `broken redirect`, `looped redirect`, `ambiguous error`, `rare status`, `chained headers`, `content sniffing`, `strict checking`, `header injection target`, `header transformation`, `hop loss`, `faulty reverse proxy`, `split response`, `multi-protocol support`, `alternate protocol`, `fallback protocol`, `http/2 push`, `h2c upgrade`, `quic handshake`, `async response hints`, `trailer field`, `connection upgrade`

***

### Port, Protocol, and Service Surface

`tcp scan`, `udp scan`, `syn packet structure`, `fin probe`, `xmas probe`, `null scan`, `idle scan`, `fragmenting scan`, `packet timing`, `port randomization`, `ephemeral port set`, `static port`, `persistent port`, `socket reuse`, `protocol mismatch`, `malformed banner`, `out-of-sequence responses`, `half-open sockets`, `protocol deviation`, `banner analysis`, `spurious response`, `response time fingerprint`, `jitter analysis`, `open relay clue`, `service alias`, `port reuse`, `session token on connect`, `protocol downgrade`, `protocol chaining`, `fallback mode`, `legacy port`, `alternative service`, `multiplexed protocol`, `dual stack listener`, `transitional socket`, `explicit proxy`, `transparent proxy`, `backplane exposure`, `split traffic evidence`, `port forwarding chain`, `hairpin nat`, `double nat`, `reverse nat`, `napt`, `mac-pinned port`, `stateful port`, `idle timer`, `conntrack`, `connection pinning`, `flap detection`, `interface enumeration`, `loopback exposure`

***

### Cloud, Container, and Infra Enumeration

`service endpoint`, `cloud region`, `multi-cloud site`, `redundant zone`, `failover host`, `virtual network`, `peered vpc`, `cidr spread`, `elastic resource`, `spot resource`, `ephemeral ip`, `reserved compute`, `cloud api endpoint`, `metering endpoint`, `access credential`, `public bucket`, `hidden bucket`, `orphaned volume`, `snapshot leak`, `backup leak`, `disk image`, `bucket policy`, `policy inheritance`, `access log`, `cross-account asset`, `stale deployment`, `misrouted service`, `deleted resource`, `preview resource`, `container image`, `orchestrator cluster`, `node ip`, `control plane`, `etcd key`, `admin endpoint`, `kube proxy`, `mounting issue`, `open dashboard`, `service account`, `auto-scaling log`, `stale container`, `shadow pod`, `leaked secret`, `pod c2c channel`, `internal envoy`, `service mesh leak`, `drifted replica`, `leftover pvc`, `unused configmap`, `hanging endpoint`, `auto-discovered node`, `misnamed service`, `split-brain failure`, `default ingress`, `nodeport smell`

***

### HTTP/HTTPS Deep Fingerprinting

`tls version`, `alpn negotiation`, `cipher suite`, `ja3 fingerprint`, `ja3s fingerprint`, `session resumption`, `session ticket reuse`, `ocsp stapling`, `x509 chain analysis`, `signature algorithm`, `extended key usage`, `certificate sprawl`, `expiry chain`, `notBefore anomaly`, `notAfter anomaly`, `self-signed cert`, `ca mismatch`, `cross-signed`, `wildcard sanction`, `extra san`, `sidCertificate`, `expired chain`, `mTLS negotiation`, `renegotiation support`, `weak cipher`, `deprecated ca`, `intermediate authority`, `trusted root anchor`, `legacy browser compatibility`, `sni behavior`, `sni-less handling`, `cross-server certificate`, `certificate transparency`, `ocsp query path`, `expired staple`, `stapling absence`, `incomplete chain`, `altname exhaustion`

***

### Host, Asset Attribution & Risk Feature Discovery

`host fingerprint`, `passive dns correlation`, `asset entropy`, `public projection`, `shared hosting marker`, `public resources`, `asset overlap`, `email pointer`, `admin pointer`, `partner domains`, `affiliate hint`, `public issue page`, `retired app`, `abandoned endpoint`, `time-based asset creation`, `update interval`, `resource churn`, `stale code`, `version drift`, `user portal`, `device fingerprint`, `browser fingerprint`, `third-party script`, `external library`, `package ecosystem leak`, `stub url`, `old favicon`, `favicon entropy`, `custom error page`, `error signature`, `spoofed header`, `x-powered mismatch`, `exposed management panel`, `debug interface`, `stale resource pool`, `hidden login page`, `secret share`, `embedded password`, `predictable path`, `crash dump`, `token leakage`, `orphaned instance`, `forgotten cache`, `persistent debug`, `client cert required`, `time signature`, `request id`, `chain id`, `unknown identifier`

***

### “Advanced Reconnaissance Tactics”
`timing enumeration`, `differential response`, `cache state probing`, `active crawler avoidance`, `honeypot detection`, `ip blacklist evidence`, `token hopping`, `header permutation`, `error permutation`, `input mutation`, `adaptive depth scanning`, `decoy signal`, `volume obfuscation`, `rate profile shifting`, `correlated resource timing`, `content length anomaly`, `chunked transfer variations`, `injected whitespace`, `recursive pattern tracing`, `transaction tracking`, `server tick`, `session id analysis`, `user id enumeration`, `obfuscated asset probing`, `x-forwarded-for trick`, `referer spoofing`, `host spoofing`, `cross-protocol interaction`, `shakeout test`, `traffic watermarking`, `header relay`, `abnormal serve time`, `time-based analysis`, `randomized probing`, `non-linear input`, `forced error`, `sequence exploration`, `regex test parameter`, `range request testing`, `resource enumeration`, `call frequency analysis`, `chain misalignment`, `interleaved asset discovery`, `directory chain leakage`, `extension sniffing`, `parameter reflection`, `error code fingerprinting`, `banned header testing`
