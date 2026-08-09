---
layout: post
title:  "Cyber-AutoAgent-ng 0.10: multi-agent refactor"
date:   2026-08-08
categories:
- cyber-autoagent-ng
comments: true
---

My latest work on Cyber-AutoAgent-ng is a large refactor. The previous agent approach is a single main agent with instructions not only for doing the security work (identifying and verifying vulnerabilities), but managing work flow. The new approach is a multi-agent system, where each agent has a narrow role. The model is more effective and recovery of model misbehavior (reasoning loop, lack of tool calls) is more effective.

Python code now manages the work flow. The instructions for the agent work flow were always very specific. I did a lot of work with prompting to convince the model to follow the work flow, but it was never satisfactory. This makes sense, models are non-deterministic by design. It felt good to delete all of that out of the system prompt.

The actor/critic pattern has been implemented for specific agents to improve their performance. After adding the critic, I was surprised to see how badly some things were behaving that I hadn't noticed! The pattern was strongly recommended in the AI Hacking Discord and with good reason. It has increased quality dramatically.

- Some of the plans, which guide the general workflow, were bad. Single phase or so abstract they were meaningless.
- Contradictory prompts were found. Some text would say "all, everything, ..." and other would say "specific, enumerate, ...". Some models could resolve that, others would get into reasoning loops. Even when resolved, the results between runs could be very different.
- Evaluation of a task status, is it done or failed, is now a critic that is fed back to the task. Previously, the main agent decided the status and its reasoning was weak. It preferred 'done' because it was easier to reason about.
- Phases were complete if there tasks reached terminal state. No concept of meeting the objective. There is a new evaluator specifically for that purpose.

The following is a list of the agents and their roles:

- **plan_creator**: creates or revises an initial high-level plan and infers operation-wide constraints
- **plan_critic**: reviews an initial plan and either approves it or returns actionable revision feedback
- **task_creator**: creates concrete current-phase tasks with finite acceptance contracts from a deterministic controller prompt
- **task_prompt_builder**: reviews core, optional-tool, and installed shell-command catalogs, then selects applicable memory, optional tools, and likely commands for one task
- **task_prompt_critic**: approves a proposed task execution prompt or returns actionable revision feedback
- **task_executor**: executes one active task objective and retains its conversation across critic-guided passes
- **task_evaluator**: reviews semantically complete acceptance ledgers and returns `done`, `partial_failure`, or `blocked`
- **phase_evaluator**: returns phase status: `continue`, `done`, `partial_failure`, or `blocked`

The **task_prompt_builder** is the biggest win. The previous design with one main agent held the entire prompt, the entire tool list, and the entire conversation. Adding the task system helped but the cognitive load was still there. Now each task gets a custom built prompt based on its objective, memory, findings, and tools specific to the objective. This releases a lot of context and inference space to focus on the task. The memory and findings give insight to the task based on what has been found.

Reporting has gotten an overhaul. A lot of it is written with Python code because it doesn't need an LLM. Parts of the report best done with inference are given to the LLM with an actor/critic cycle. This increases the report accuracy.

Using multiple agents with narrow tasks and customized prompts is a huge improvement. The context limitations have prevented me from using most MCP servers. I'm looking forward to what Cyber-AutoAgent-ng will do with MCP tools.

After the 0.10 release, look for:
- Credential store, both provided by the user and from self-registration on target sites.
- Technique agent to learn techniques from the Internet and its own experience. The result is written in a document tailored for Cyber-AutoAgent-ng agents.
- Proxy support to send everything through your intercepting proxy of choice.

Here is a video of `gemma4:26b-mlx` hacking DWVA. Reporting isn't ready to present yet, I'll post that later.

<video controls width="100%">
  <source src="/extra/video/dvwa-2026-08-06.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>
