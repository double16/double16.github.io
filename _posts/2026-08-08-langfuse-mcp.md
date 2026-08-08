---
layout: post
title:  "langfuse-mcp for optimizing prompts"
date:   2026-08-08
categories:
- cyber-autoagent-ng
- tools
comments: true
---

Today I tried using langfuse traces to look for prompt improvements in Cyber-AutoAgent-ng. I've been using coding agents to review my operation logs for opportunities for improvement and recommend code changes. It is a helpful cycle. The agent is able to infer things much faster than I am and provide some great solutions. There is valuable information in langfuse traces, so I wanted to use it to improve the software. Several of my agent prompts are generated from data and other agents. Analyzing the result rather than the code that produces it should provide good insights.

A quick search resulted in a langfuse MCP server designed for this: [langfuse-mcp](https://github.com/avivsinai/langfuse-mcp). It has an MCP server and skill designed for the investigations I want. At the time of this writing, it was updated two days ago, so an active project.

Installation of the MCP server into `codex` was easy.

```shell
codex mcp add langfuse \
  --env LANGFUSE_PUBLIC_KEY=pk-... \
  --env LANGFUSE_SECRET_KEY=sk-... \
  --env LANGFUSE_HOST=http://localhost:3000 \
  -- uvx langfuse-mcp
```

Adding the skill to the project was also easy. In the project directory run the following command. The project instructions include the `-g` (global) option, but `PromptScript` failed with the global install. Installing locally worked.

```shell
npx skills add avivsinai/langfuse-mcp -y
```

In langfuse look up a session ID, for Cyber-AutoAgent-ng this is the operation ID, for example "OP_20260807_214305".

In Codex, ask for a review:

```
> Review the langfuse session OP_20260807_214305 to provide recommendations for prompt improvements.

• The session shows a clear pattern already: the report loop repeatedly repaired deterministic factual defects (host typos, incomplete tool lists, and required fallback wording), while one report-generation pass
  consumed 172,527 input tokens and ran about 3.3 hours. I’m tracing those failures back to the prompt/data-boundary design so the recommendations address causes rather than just symptoms.

...
```

So the reporting was hurting 😆. After fixing that, I ran it again, ignoring report traces.

```
• I reviewed OP_20260807_214305 and excluded all reporting traces (report_generator/report_critic).

  Main prompt recommendations:

  1. Make acceptance-disposition rules explicit.

  In task trace d580b411d97d3b2a9ad74c3a00be9c6f, the executor repeatedly called record_task_acceptance with finding_candidate, producing:

  > “requires a finding created by this task. Call store_finding first.”

  Add a compact decision rule:

  Use finding_candidate only after this task successfully calls store_finding.
  If the finding already exists, use existing_finding.
  Do not use finding_candidate merely because validation confirmed an existing finding.

  2. Include parent criterion IDs in task-creator context.

  Task creators in d9d0cfadb237789945d5256ec4597eaf and 43054f4949611aba4db1bb2b5fdf0984 used replacement_of without valid supersedes_criteria, causing:

  > “supersedes_criteria must identify existing acceptance criteria on the parent task”

  The prompt context exposed parent task metadata but not the criterion IDs needed for replacement. Include each failed/blocked parent’s criterion ID and description, or explicitly prohibit replacement_of when those
  IDs are unavailable.

...
```

Very cool. I asked Codex to propose a plan to fix these things and there are good recommendations.

I've found asking the AI to analyze the program output (logs, reports and now traces) has been valuable. When analyzing the prompts in code, it found contradictions, redundancy and prompts that don't match the code. I'm looking forward to the insights analyzing langfuse traces will bring.
