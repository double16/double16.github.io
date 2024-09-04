---
layout: post
title:  "Crawling Large Sites"
date:   2024-09-03 11:38:10 -0500
categories: cyber recon
comments: true
---

I've been working on bug bounties and the tools I use for crawling HackTheBox machines do not scale well for large, public sites. These are a few things I've learned, and my methodology will improve as time goes on.

## GUI Tools Choke

My go-to intercepting proxy is ZAP. I won't give an exhaustive explanation of my choice, but
mentioned a few things. ZAP performs passive scanning as a site is browsed or crawled
(aka. spidered). There are a lot of useful alerts given by this. The requests and responses,
including headers and bodies, can be searched for content. It would be advantageous to scan a
large site. Burp Suite has similar features.

The issue is that crawling a large site can approach tens or hundreds of thousands of requests. Excluding out of scope domains from the proxy helps, but it isn't enough. At this number of
requests operations slow down to become unusable. Opening and closing the ZAP session is slow.
I've also experienced where ZAP crashes or my VM crashes, it corrupts the session file. That is
a lot of work lost.

## Command Line

My solution is to not use ZAP or Burp Suite for crawling. I use these tools for manual work. Instead,
I use the command line tool `katana` to crawl the entire site. The results are stored in JSON in a text file. Command line tools can be used to digest the data.

### Passive Crawling

Passive crawling is using sites like [The Wayback Machine](https://web.archive.org) to query
historical URLs. The `-passive` argument enables this feature instead of crawling the site itself.

```shell
katana -u https://example.com -passive
  -omit-raw -omit-body
  -o katana-passive-example.com.json -jsonl
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0'
```

### Crawling

```shell
katana -u https://example.com -js-crawl -jsluice -known-files all
  -field-scope fqdn -display-out-scope
  -form-extraction -ignore-query-params -strategy breadth-first
  -omit-raw -omit-body 
  -rate-limit 6
  -o katana-example.com.json -jsonl
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0' -retry 3
```

### Headless Crawling

Headless crawling uses the Chromium browser to crawl the site. For dynamic web sites this may yield more results. The `-headless` argument enables this feature.

```shell
katana -u https://example.com -headless -js-crawl -jsluice -known-files all
  -field-scope fqdn -display-out-scope
  -form-extraction -ignore-query-params -strategy breadth-first
  -omit-raw -omit-body
  -rate-limit 6
  -depth 5 -retry 3
  -o katana-headless-example.com.json -jsonl
```

### Argument Description

Read the [katana docs](https://github.com/projectdiscovery/katana) to fully understand
its options and behavior. These are the ones I've found useful so far.

| Argument | Description                                                                                                           |
|----------|-----------------------------------------------------------------------------------------------------------------------|
| -js-crawl | Scans javascript for URLs.                                                                                            |
| -js-luice | Uses the JSLuice library to extract more URLs.                                                                        |
| -known-files all | Look for robots.txt, sitemap.xml, etc.                                                                                |
| -field-scope fqdn | Don't crawl outside of the fully qualified domain.                                                                    |
| -display-out-scope | Output links to out of scope URLs without accessing them.                                                             |
| -form-extraction | Extract form data.                                                                                                    |
| -ignore-query-params | Ignore query params when determining if a URL has been visited. Keeps the scan from growing out of control.           |
| -strategy breadth-first | Most features of a site are identified by the first or second depth of the path. This option discovers these earlier. |
| -omit-raw | Omit the raw request/response data, otherwise local files can grow large.                                             |
| -omit-body | Omit the raw request/response bodies, otherwise local files can grow large.                                           |
| -rate limit 6 | Limit to 6 requests per second. Attempts to prevent being blocked or overwhelming the site. |
| -o | The output file                                                                                                       |
| -jsonl | JSON Line output, each line is a JSON document for a request and response.                                            |
| -H | Specifies an HTTP header, in this case a custom user agent.                                                           |

## Analyzing

The output is a JSON payload, one request/response per line, perfect for command line tools.

`jq` is the primary tool I use to extract fields. For example, to get a list of all visited
URLs, one per line:

```shell
cat katana-example.com.json | jq -r .request.endpoint
```

To extract parts of the URL, use TomNomNom's [`unfurl`](https://github.com/tomnomnom/unfurl):

```shell
cat katana-example.com.json | jq -r .request.endpoint | unfurl paths
```

[TomNomNom](https://github.com/tomnomnom) uses the command line at lot and has developed tools
that will help in this approach. Check out his GitHub. Here's a video I enjoyed watching his command line skills: [NahamSec](https://youtu.be/SYExiynPEKM?si=FffUMrrv5sCdDTgM) .

ZAP and Burp Suite both allow importing a text file of URLs. Once I have a set of URLs I want to investigate further, I import into ZAP.

## Conclusion

When working with sites at large scale, I need to get creative instead of wasting time waiting for
tools to run. ZAP has a command line mode and docker image that I plan to experiment with to see if
I can get it to perform passive scans at scale.
