---
layout: post
title:  "Cyber-AutoAgent-ng Memory Refactor Needed"
date:   2026-03-26
categories:
- cyber
- ai
- tools
comments: true
---

While testing the task system I found incorrect assumptions about how mem0 works. For plans and tasks it is being used as a NoSQL database and it is not. For findings it seems fine, although the stated benefit and use case of mem0 isn't being leveraged.

So I need to add a database like sqlite. Sqlite will work for local deployment. OpenSearch is already implemented for memory for distributed deployment. I need to look into it to see if it can support the plan and task memory.

The specific problem is that updating a memory item doesn't support metadata. I've gone to deleting older records and adding new. Delete isn't always working and the entire flow is unstable.

The agent itself won't need changed, the functionality is already behind specific tools for manging plans and tasks.
