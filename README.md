# WHOISWATCHER

## Install

```bash
go install -v github.com/BuffaloWill/whoiswatcher/cmd/whoiswatcher@latest
```

## Overview

WHOIS data is an excellent resource for identifying apex domains owned by a company. 
Additionally, there are 50k to 400k+ new domains registered every day. 

whoiswatcher was built to:

* Perform large sets of whois lookups quickly. It can be run in lambda or with serverless resources.

* Given a large set of domains as input, whoiswatcher will alert you of a domain in your scope (e.g. registrant email) 
For example, if you feed it a list of yesterday's registered domains ([Daily Newly Registered Domains](https://www.whoisds.com/newly-registered-domains))
and there is a matching artifact to look for (e.g. registrant email) in your configuration; it will print to stdout. 
The configuration can also combine two pieces of information. For example a domain name (e.g. Tesla) plus the registrar
they typically use (e.g. DNSination). See Use Cases below for more examples.

* whoiswatcher is designed to be fast, configurable, and with predictable output. For example, you can provide a single 
domain from stdin or a large set in a file and store searchable JSON output.

### Useful Input

* Daily List of Newly Registered Domains: https://www.whoisds.com/newly-registered-domains

* Cisco Umbrella Top 1 Million Domains: https://umbrella-static.s3-us-west-1.amazonaws.com/index.html

## Use Cases

### Simplest Use Case

```bash
echo fidelity.com | whoiswatcher
```

### Downloading Newly Registered Domains

whoiswatcher can download a list of NRD from the past 24 hours from https://www.whoisds.com. Provide a directory to
store the file:

```bash

whoiswatcher --nrd /data/nrd/

```

### Getting Alerted on an Artifact

First, we need to set a list of components (e.g. email, organization, phone, etc.) to watch in `.watchlist.yaml`:

```yaml
- key: email
  type: contains
  value: "@bankofamerica.com"         # match for bankofamerica.com
- key: organization
  type: contains
  value: Google LLC                   # match for youtube.com
- key: phone
  type: contains
  value: 6173921636                   # match for fidelity.com
- key: domain                         # match for domain squatting 
  type: contains
  value: company.sucks
- combo:                              # match for teslamotors.com
    - key: domain
      type: contains
      value: tesla
    - key: organization
      type: contains
      value: DNStination
```

Then we can feed in a list of domains or just a single domain to alert on along with our watchlist:

```bash
echo teslamotors.com | ./whoiswatcher -w .watchlist.yaml
```

Result:

```bash
Combo Match: [{domain contains tesla} {organization contains DNStination}]
{"domain":{"id":"96457825_DOMAIN_COM-VRSN","domain":"teslamotors.com","punycode":"teslamotors.com","name":"teslamotors","extension":"com" ...
```

A failed match will not print anything:

```bash
echo yahoo.com | ./whoiswatcher -w .watchlist.yaml
```

### Searching Historic Domains

whoiswatcher is most realistically served by saving results to a file and then analyzing them later. Let's say 
in the past we performed a WHOIS lookups using whoiswatcher on a large set of domains and stored the results to a 
JSON file. Later we want to come back and search through the entries using an updated watchlist:

```bash
./whoiswatcher -j results.json -w .newwatchlist.yaml
```

### Analyzing a large input list (Not serverless)

To print results from lookups even with a watchlist use `-v`:

```bash
./whoiswatcher -v -f large_domain_list.txt
```

### Quick Lookup 

You can quickly find just the email or phone of a domain with `-u`:

```bash
echo fidelity.com | ./whoiswatcher -u email
{"domain":{"id":"1047386_DOMAIN_COM-VRSN","domain":"fidelity.com","punycode":"fidelity.com","name":"fidelity","extension":"com","whois_server":"whois.corporatedomains.com","status":["clienttransferprohibited","serverdeleteprohibited","servertransferprohibited","serverupdateprohibited"],"name_servers":["a1-188.akam.net","a2-65.akam.net","a8-64.akam.net","udns1.cscdns.net","udns2.cscdns.uk"],"created_date":"1996-08-31T04:00:00Z","created_date_in_time":"1996-08-31T04:00:00Z","updated_date":"2023-08-27T05:38:12Z","updated_date_in_time":"2023-08-27T05:38:12Z","expiration_date":"2024-08-30T04:00:00Z","expiration_date_in_time":"2024-08-30T04:00:00Z"},"registrar":{"id":"299","name":"CSC Corporate Domains, Inc.","phone":"+1.8887802723","email":"domainabuse@cscglobal.com","referral_url":"www.cscprotectsbrands.com"},"registrant":{"name":"FMR LLC","organization":"FMR LLC","street":"245 Summer Street","city":"Boston","province":"MA","postal_code":"02210","country":"US","phone":"+1.6173921636","fax":"+1.6172170836","email":"dnsadmin@fmr.com"},"administrative":{"name":"FMR LLC","organization":"FMR LLC","street":"245 Summer Street","city":"Boston","province":"MA","postal_code":"02210","country":"US","phone":"+1.6173921636","fax":"+1.6172170836","email":"dnsadmin@fmr.com"},"technical":{"name":"FMR LLC","organization":"FMR LLC","street":"245 Summer Street","city":"Boston","province":"MA","postal_code":"02210","country":"US","phone":"+1.6173921636","fax":"+1.6172170836","email":"dnsadmin@fmr.com"}}

Registrar Email:domainabuse@cscglobal.com
Administrative Email:dnsadmin@fmr.com
Technical Email:dnsadmin@fmr.com
```

### Alert on Multiple Components

Set the watchlist to include two components in a lookup:

```yaml
- combo:                              # match for teslamotors.com
    - key: domain
      type: contains
      value: tesla
    - key: organization
      type: contains
      value: DNStination
```

Then we can feed in a list of domains or just a single domain to alert on along with our watchlist:

```bash
echo teslamotors.com | ./whoiswatcher -w .watchlist.yaml
```

Result:

```bash
Combo Match: [{domain contains tesla} {organization contains DNStination}]
{"domain":{"id":"96457825_DOMAIN_COM-VRSN","domain":"teslamotors.com","punycode":"teslamotors.com","name":"teslamotors","extension":"com" ...
```

###  Additional Features

* Whoiswatcher will do it's best to queue domains that failed due to rate limiting and then attempt to rerun after a specified time period.
* IPv6 or IPv4 proxying


