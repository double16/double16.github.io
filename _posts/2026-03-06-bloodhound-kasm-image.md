---
layout: post
title:  "BloodHound Ephemeral Docker Container"
date:   2026-03-06
categories:
- cyber
- tools
comments: true
---

If you use BloodHound, I maintain an ephemeral docker image that runs with Kasm or standalone. (I enjoy Kasm for many reasons, check it out sometime.) It has a quicker start-up time because I let the database initialize at build time rather than runtime.

The ephemeral nature works great for CTFs or short engagements.

Disclaimer: This is meant for ephemeral, local use only.

https://gallery.ecr.aws/bramblethorn/kasm/bloodhound](https://gallery.ecr.aws/bramblethorn/kasm/bloodhound)

