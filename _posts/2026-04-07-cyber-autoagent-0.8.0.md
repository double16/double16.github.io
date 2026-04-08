---
layout: post
title:  "Cyber-AutoAgent-ng 0.8.0"
date:   2026-04-07
categories:
- cyber-autoagent-ng
- ai
- tools
comments: true
---

Cyber-AutoAgent-ng 0.8.0 is available. This is a big change with much improved coverage and performance optimizations.

[https://github.com/double16/Cyber-AutoAgent-ng/releases/tag/v0.8.0](https://github.com/double16/Cyber-AutoAgent-ng/releases/tag/v0.8.0)

Features:
- Task system (#26)
- System prompt optimization
- Rejection of early phase transition or termination (#89)
- Ollama context length set via `OLLAMA_CONTEXT_LENGTH` env var (models do not need to be extended)
- Option for continuing an operation
- Option for re-generate a report (#21)
- Improved reporting with more finding detail
- Add a methodology appendix to the report
- Modules may be nested in directories (#12)
- Add memory model config to React UI (#7)

# Task System

The most important update in this release is a new task system. The agent creates narrowly scoped tasks from tool results which will be used to drive further work. Target task-based tools serve the agent the next task so the agent doesn't need the cognitive load of managing tasks.

In addition to task, the conversation budget code keeps planning based messages during pruning. These messages represent state. If they are lost, the model loses its direction.

- Latest plan
- Active task + evidence paths upon which the task was created

Also, when the agent won't progress and there are active tasks, the conversation is rebuilt to include the plan and active task. This has shown to be effective to keep the agent progressing.

Creating tasks and serving them up to the agent was straight forward. The agent happily made tasks. I did need to add fuzzy detection of duplicates. The difficulty is that LLMs want to finish something and provide an answer to the user. I want the agent to work, keep going, keep exploring things. So the system prompts became very important to urge the agent on. There are points were it just wanted to be done, so I added code to reject tool calls to moving the plan forward or calling the `stop` tool. The failure message I return includes the active task and instructions to keep moving forward.

## Models

My go-to local model has been `qwen3-coder:30b` with at least a 40K context window, 49K if my Mac unified memory allows. It does less reasoning, issuing tool calls sooner. However, the task system seems that it needs more reasoning.

Models I've found successful after this change:
- `qwen3:30b`, `qwen3:14b`
- `gpt-oss:20b` (it tends to stop issuing tool calls after 25-30 steps)

What does not work:
- `qwen3.5:9b`, won't make tool calls consistently, may be the model or small parameter size

# System Prompt Optimization

The task system is intended to increase coverage. The system prompts were directed towards reducing steps, a direct conflict. I spent time re-writing prompts to balance coverage and efficiency, de-duplicating instructions, reducing confusion, etc.

# Reporting

The task system increases the coverage, which increases findings, which increases reporting. The previous report generator was designed to report on a few of the highest severity findings. The new report generator is designed to report on all findings, with more detail. The implementation splits up the work into multiple agent calls for better model comprehension and less context usage. Now the reporting takes quite a bit longer. There isn't progress reported, which I intend to fix.

# Ollama Context Length

I found that the Ollama `/api/chat` API accepts a `num_ctx` value to set the context length. Previously I've been extending models using `Modelfile` to set the context length. This still works, but it is much less work to set the environment variable `OLLAMA_CONTEXT_LENGTH`. The Ollama server supports this variable but ALL models use it. If set in the CAA process or docker environment, only the agent models use it.

# Continue Operation

Operations can be continued using the `--continue` command-line option. Optionally, an operation ID (ex: `OP_20260310_152846`) can be specified. Otherwise, the last operation will be continued. The main use case is continuing in case of a provider failure.

# Re-run Report

A report can be re-generated using the `--report` command-line option. Optionally, an operation ID (ex: `OP_20260310_152846`) can be specified. Otherwise, the last operation will be reported. This works whether the operation completed or not.

Some use cases:
- Operation fails and cannot be continued
- Report prompt is changed
