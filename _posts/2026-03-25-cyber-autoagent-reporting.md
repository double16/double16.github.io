---
layout: post
title:  "Cyber-AutoAgent-ng Reporting Improvements"
date:   2026-03-25
categories:
- cyber
- ai
- tools
comments: true
---

As expected, I broke reporting with the task system. The coverage is greatly improved, adding far more findings and observations. So before I can release 0.8.0 I need to address this, at least so reports finish.

First thing is to write the data used by the reports to a JSON file in case an outside process wants to use it. You can find it in the outputs folder as `security_assessment_report.json`.

The reporting approach was to report on the top 5 or so findings, criticals, highs, etc. and summarize the rest. I've changed this to report on all findings. There is still an executive summary. I've added a methodology appendix to the end to show the plan and tasks.

The context window was getting large. Each finding, observation, and section uses it's own agent call to keep the context manageable. This is working pretty well.

Now to the modules, which need work. There is `report_prompt.md` that was appended to the report agent prompt. Now that there are several agents, this needs to be split up. I've also noticed duplication in the module-specific prompts. I'll take a first look at this, but likely wait for fine-tuning later. I really want to get 0.8.0 out the door.

Mostly the reports will render in Obsidian so I can export a PDF. Some of the Mermaid diagrams are failing because of character issues, I think forward slash. I've easily got a 45 page report :p, and that's not with full coverage of the target.

