---
layout: post
title:  "Releasing shyhurricane: MCP/RAG for Large Web Apps"
date:   2026-03-20
categories:
- ai
- tools
comments: true
---

Shipped the first release of ShyHurricane, an MCP server built to make AI more effective at offensive security testing of web applications. It is aimed at a problem I kept seeing in practice: LLMs waste time and tokens on noisy spidering, repeated curl requests, and long-running scans instead of building useful coverage and analyzing what matters.

ShyHurricane gives the model a better operating environment for web assessment work. It provides purpose-built tools for port scanning, spidering, directory busting, URL indexing, and querying previously captured content, then stores and indexes what it finds so the model can work from collected evidence instead of re-hitting the target over and over. It also supports embedding-backed search across indexed web content, including HTML, JavaScript, CSS, XML, and headers, and can ingest external data from sources like Katana, Burp Logger++ CSV, and browser or proxy extensions for Chrome, Firefox, Burp Suite, and ZAP.

Check it out at [https://github.com/double16/shyhurricane](https://github.com/double16/shyhurricane).
