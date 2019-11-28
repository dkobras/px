// proxy configuration to verity various functionalities in test infrastructure
function FindProxyForURL(url,host)
{
  // JS string matching functions are case-sensitive, so provide a lower-case version of the host name for convenience, to be used in subsequent rules
  var lc_host = host.toLowerCase();

  // loopback needs no proxy
  if (host.substring(0, 4) == "127." ||
      host.substring(0, 9) == "localhost" )
      { return "DIRECT"; }

  // plain hostnames (no FQDN) should bypass proxy
  if (isPlainHostName(host))
      { return "DIRECT"; }

  // test specific host-matching functions, and send requests to NTLM-authenticating proxy
  if (
      url.substring(0, 12) == "http://ntlmserver" ||	
      lc_host == "ntlmserver.example.com" ||
      shExpMatch(lc_host, "ntlm*.example.com")
     )
      { return "PROXY squid-ntlm:3128"; }

  // test domain matching, and send requests to SPNEGO-authenticating proxy
  if (dnsDomainIs(lc_host, ".example.com"))
  {
	  // test load-balancing based on last octect of IP address of host's first IP address;
          // once we're at it, also test fallback for unavailable proxies
          var mod3 = myIpAddress().split('.')[3] % 3;
          if (mod3 == 0) {
                  return "PROXY doesnotexist-1:3128; PROXY doesnotexist-2:3128; PROXY squid-spnego:3128";
          } else if (mod3 == 1) {
                  return "PROXY doesnotexist-2:3128; PROXY squid-spnego:3128; PROXY doesnotexist-1:3128";
          } else {
                  return "PROXY squid-spnego:3128; PROXY doesnotexist-1:3128; PROXY doesnotexist-2:3128";
          }
  }

  // send all other requests to open proxy (no authentication required)
  return "PROXY squid-noauth:3128";
}

