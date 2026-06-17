---
layout: post
title:  "Cyber-AutoAgent-ng 0.9.0"
date:   2026-06-17
categories:
- cyber-autoagent-ng
- ai
- tools
comments: true
---

Cyber-AutoAgent-ng 0.9.0 is available.

[https://github.com/double16/Cyber-AutoAgent-ng/releases/tag/v0.9.0](https://github.com/double16/Cyber-AutoAgent-ng/releases/tag/v0.9.0)

- Replace React UI model pricing with model.dev. (Fixes #55)
- Configure Ollama keep-alive for models to avoid extra start up time. Defaults to 30m.
- Add bug bounty header markers. (Fixes #63)
- Add idor_specialist tool. (Fixes #22)
- Publish tools image to `public.ecr.aws/bramblethorn/cyber-autoagent-ng/tools:latest`. (Fixes #20)
- Only pass temperature if the model supports it.
- Refactor output of the following tools to avoid agent misdirection. (Fixes #105)
- mem0_list, mem0_retrieve, list_uncompleted_tasks, get_plan response, store_plan
- Improve rate limiting with back-off when HTTP responses 429 (rate limit) and 503 (service unavailable) occur. This feature is always enabled.
- Fix mem0_retrieve bug, missing 'cross_operation' reference.
- React UI requires Node.js 22.x or higher.
- Python dependency updates.

0.10.0 is going to be a big refactor. I'll be replacing the one "main" agent with multiple purpose-built agents. The workflow will be controlled by procedural code. That will allow the agents to focus on specific tasks and remove a lot of cognitive load. I'll also be able to leverage memory as each agent is started. Actor/critic pattern throughout. These changes should make a huge difference.
