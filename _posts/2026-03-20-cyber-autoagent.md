---
layout: post
title:  "Cyber-AutoAgent-ng"
date:   2026-03-20
categories:
- cyber
- ai
- tools
comments: true
---

The latest open source project I've been working on is a fork of the archived [Cyber-AutoAgent](https://github.com/westonbrown/Cyber-AutoAgent). It is an offensive security agent with broad reasoning and goals at the top-level with plugable modules specifying more narrow targets. My fork is at https://github.com/double16/Cyber-AutoAgent-ng.

(Also keep an eye out for my shyhurricane project. It is my RAG solution to large web apps, but it needs a good agent, so I need the changes talked about here to be working first.)

My near-term goals for this project:
 - Operationalize it. Very good proof-of-concept work by the original author and contributors.
 - Target local small to mid-size models. Not everyone has $$$$ and data privacy is a big concern.
 - Large scale recon analysis and reports on web apps, networks, source code, mobile, etc.
 - Check out the GitHub issues for milestones.

Anti-goals:
 - Full exploitation. I find a majority of cycles are spent on exploitation. Once the model tells me the vuln, I can fairly quickly exploit it myself.
 - "Autonomous pentester". Computers are tools, tools are meant to free humans to do the creative work we excel at and enjoy.
 - Taking over the world. Boring. Owning the world is no good for an introvert, too much input.

Recently I was encouraged to write about my experiences as I go along. Seems like a good idea and looking back there are some conclusions I made that I wish I had a journal of the journey.

My primary machine is a MacBook Pro M1 with 32GB RAM. The results I'll be writing about are from my laptop (Ollama) or free/cheap models on OpenRouter, NVIDIA NIM, etc. The caveat with the free/cheap models are that your data is likely being used for training or publishing. Some use cases are ok, such as evaluating intentionally vulnerable apps. The engineering to get smaller models to produce good results should result in larger models being more effective and efficient. (Maybe only $$ instead of $$$$.)

If you're going to ask if I've seen how **amazing** the frontier models are, and why am I not in love with them, the answer is: yes, I am fully aware of the frontier models. Boring. Where is the challenge? Where is the bit twiddling optimizations that make a 14b model get the results that matter? Also, where are you all getting all that money that's making the big corps rich??

A lot of the work has been tuning configuration and maintaining an efficient context. There are competing pressures with keeping the context small, yet having enough information for the model to reason.

You'll see the current version is 0.7.0, which is primarily tool/sheel calling improvements. The next milestone is 0.8.0 and it is big :p

The biggest changes are a task system and system prompt optimization. The task system is kept in long term memory and is key to allowing large scale operations. Context memory is not enough, even with frontier models. Along with the task system, system prompts need to change and be optimized.

# Task System

The agent creates narrow tasks from tool results which will be used to drive further work. Memory tools serve the agent the next task so the agent doesn't need the cognitive load of managing tasks.

CAA has had problems with coverage. My tests on JuiceShop and DVWA show a large increase in coverage.

In addition to task, the conversation budget code keeps certain messages because they represent state. If they are lost, the model loses its direction.

- Objective
- Last plan
- Active task + evidence paths upon which the task was created

## Models

My go-to local model has been `qwen3-coder:30b` with at least a 40K context window, 49K if my Mac unified memory allows. It does less reasoning, issuing tool calls sooner. However, the task system seems that it needs more reasoning.

Models I've found successful after this change:
- `qwen3:30b`, `qwen3:14b`
- `gpt-oss:20b` (it tends to stop issuing tool calls after 25-30 steps)

What does not work:
- `qwen3.5:9b`, won't make tool calls consistently, may be the model or small parameter size

## Agent Stalling

A problem I've been dealing with for a while is the agent stalling, or failing to make progress by issuing tool calls.

For example, with `gpt-oss:20b` I get this:

```
**How does this move me toward OBJECTIVE or target coverage?**  
The logout page is part of the DVWA surface; confirming the absence of XSS here ensures coverage of the login/logout flow and validates that no reflected input is processed. This completes the XSS coverage for the logout endpoint.

**Next step:**  
Proceed to the next phase‑1 task: enumerate all endpoints, parameters, and authentication flows. This will provide the necessary coverage for subsequent hypothesis and exploitation phases.
```

Ok, great gpt-oss, why aren't you issuing tool calls?

When detecting this case, I'm adding user messages like the following to the conversation:

- `Re-emit your last response as valid tool calls. No prose. No XML. At least one tool call is required to progress towards the objective. Reflect on next steps to reach the objective.`
- `**MANDITORY ACTION**: Take your time to decide which tool to call for your next step. This tool MUST be called next to make progress.`

Sometimes this works, other times the model refuses to issue tool calls.

The next idea I'm trying is to rebuild the context with the latest plan, memories and active task. That is working to make progress. I've added code to detect duplicate tasks, so we'll see how it progresses.

I'm thinking of trying a sub-agent per task and loading the initial conversation with the plan, task and previews of the evidence relevant to the task. That could be a lot more work and I'm keen to release what I have so far.

# System Prompt Optimization

The task system is intended to increase coverage. The system prompt was directed towards reducing steps, a direct conflict. I spent time re-writing prompts to balance coverage and efficiency, de-duplicating instructions, reducing confusion, etc.

The task management prompt seems too large, but the content there is needed to keep the agent rolling. If I try using sub-agents, I'll also try moving task management into python code and have the agent create tasks. The result of the sub-agent would indicate the task is done or failed, taking that logic out of the context.
