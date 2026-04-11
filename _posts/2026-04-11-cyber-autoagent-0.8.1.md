---
layout: post
title:  "Cyber-AutoAgent-ng 0.8.1"
date:   2026-04-11
categories:
- cyber-autoagent-ng
- ai
- tools
comments: true
---

Cyber-AutoAgent-ng 0.8.1 is available. These are bug fixes and small enhancements based on testing after the 0.8.0 release. 

[https://github.com/double16/Cyber-AutoAgent-ng/releases/tag/v0.8.1](https://github.com/double16/Cyber-AutoAgent-ng/releases/tag/v0.8.1)

- Support thinking/reasoning for LiteLLM (#24)
- Activate a new task and return in `create_tasks` tool
- Report generation ensures a blank line before Markdown tables
- advanced_payload_coordinator.py: only do param discovery if no params are provided, limit scans to 5 params

# Support thinking/reasoning for LiteLLM

I added support for thinking in Ollama in 0.8.0 and did some important work making thinking models perform better. I neglected to add that to LiteLLM.

# Activate a new task and return in `create_tasks` tool

Some models did not follow the instruction to call `get_active_task` after `create_tasks`. See my coming post about using tool output to guide the agent. The output of `create_tasks` now will activate a task if there isn't one and return it.

# advanced_payload_coordinator.py

This tool was taking a very long time. It turns out that when the agent gives the tool a set of parameters, parameter discovery is done anyway and all parameters are scanned. This change only uses parameters that are provided. (If none are provider, parameter discovery is performed). A limit of five parameters are scanned by the tools to keep the runtime reasonable.
