/*
  Network Livehunt YARA ruleset template

  Learn more about writing network Livehunt YARA rules at
  https://developers.virustotal.com/docs/nethunt.

  Network Livehunt allows you to match URLs, domains and IP addresses
  reports. In the case of URLs, you can also match the downloaded
  contents, as if it was a regular file.
  A ruleset is a collection of one or more Livehunt rules. A ruleset containing 3
  YARA rules will consume 3 Livehunt rule credits. 2 rulesets, one containing 2
  YARA rules and another one containing 3 YARA rules, will consume 5 Livehunt
  rule credits.
*/
import "vt"

rule domain_template
{
  meta:
    author = "Gavin Knapp"
    description = "monitor for new onmicroosft.com domains that are used to impersonate your business"
    target_entity = "domain"
  condition:
    //vt.net.domain.new_domain and
    ( vt.net.domain.raw startswith "yourkeyword" and vt.net.domain.raw endswith ".onmicrosoft.com" ) and not 
    ( vt.net.domain.raw == "yourlegitdomain1.onmicrosoft.com" or vt.net.domain.raw == "yourlegitdomainN.onmicrosoft.com" )
}

