---
layout: page
title: Projects
permalink: /projects/
---

# Cyber-AutoAgent-ng

[https://github.com/double16/Cyber-AutoAgent-ng](https://github.com/double16/Cyber-AutoAgent-ng)

Cyber-AutoAgent-ng is a proactive security assessment tool that autonomously conducts intelligent penetration testing with natural language reasoning, dynamic tool selection, and evidence collection using AWS Bedrock, litellm, or local Ollama models with the core Strands framework.

# shyhurricane

[https://github.com/double16/shyhurricane](https://github.com/double16/shyhurricane)

ShyHurricane is an MCP server to assist AI in offensive security testing. It aims to solve a few problems observed with
LLMs executing shell commands:

1. Spidering and directory busting commands can be quite noisy and long-running. LLMs will go through a few iterations to pick a suitable command and options. The server provides spidering and busting tools to consistently provide the LLM with usable results.
2. Models will also enumerate websites with many curl commands. The server saves and indexes responses to return data without contacting the website repeatedly. Large sites, common with bug bounty programs, are not efficiently enumerated with individual curl commands.
3. Port scans may take a long time causing the LLM to assume the scan has failed and issue a repeated scan. The port_scan tool provided by the server addresses this.

An important feature of the server is the indexing of website content using embedding models. The `find_web_resources` tool uses LLM prompts to find vulnerabilities specific to content type: html, javascript, css, xml, HTTP headers. The content is indexed when found by the tools. Content may also be indexed by feeding external data into the `/index` endpoint. Formats supported are `katana jsonl`, `hal json` and Burp Suite Logger++ CSV. Extensions exist for Burp Suite, ZAP, Firefox, and Chrome to send requests to the server as the site is browsed.

# media-hare

Sundry tools for maintaining a personal media library. Rabbits (hares) like to be clean and are frequently grooming. This project is how I learned python. The tools here are intended to groom your media files for various purposes such as:
- Transcode to storage optimized codecs
- Cut commercials from DVR recordings using genetic algorithms
- Subtitle transcribing
- Profanity filtering
- Integration with Plex Media Server

[https://github.com/double16/media-hare](https://github.com/double16/media-hare)

# Contributions

I love open source. I can add features or fix things myself and contribute back. I like sharing work I've done, just as athletes invite people to their games or artists hang their work.

## ZAP

The Zed Attack Proxy (ZAP) is one of the world’s most popular free security tools and is actively maintained by a dedicated international team of volunteers.

- [https://github.com/zaproxy/zap-extensions](https://github.com/zaproxy/zap-extensions/pulls?q=author%3Adouble16+is%3Apr)
- [https://github.com/zaproxy/zaproxy](https://github.com/zaproxy/zaproxy/pulls?q=author%3Adouble16+is%3Apr)
