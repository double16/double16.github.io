---
layout: post
title:  "Using Tool Outputs to Direct Agents"
date:   2026-05-07
categories:
- cyber-autoagent-ng
- ai
comments: true
---

As I was developing the task system for [Cyber-AutoAgent-ng](https://github.com/double16/Cyber-AutoAgent-ng), I found that system prompt instructions are not always good enough to move the agent forward. Tool output must be carefully considered. Output can either misdirect the agent or help with the desired direction.

Contract-driven development defines the specific inputs and outputs of a function or method. The function should do one thing well. When writing tools for a LLM to call, I naturally would think the same way. If the function is well-defined to the model, it will know when to call it, which inputs to send and understand the meaning of the outputs. I assumed it would understand the output is data. Not so 😐

The model will not necessarily distinguish between data and instructions. I'll show two tools I've specifically written the output to direct the agent. I found this necessary because originally there were prompt instructions to call two tools in succession because they had a dependency. I've also seen output that was meant to indicate "success" only, being taken as instructions and misdirecting the agent flow.

## create_tasks

### First Iteration

The first iteration of the tool is naive. More data is better, take what you can use, ignore the rest. LLMs don't do that, and shouldn't.

The model inferred a lot of misdirection from the output.

```json
[
  {
    "event": "ADD",
    "task_uid": "2b4166e3-711b-48b3-a25c-3af6e99a057c",
    "title": "...SNIP...",
    "objective": "...SNIP...",
    "status": "...SNIP...",
    "phase": 1,
    "evidence": "...SNIP..."
  },
  {
    "event": "ADD",
    "task_uid": "b151c29a-5176-4fdb-a42a-cf2a15ac6602",
    "title": "...SNIP...",
    "objective": "...SNIP...",
    "status": "...SNIP...",
    "phase": 1,
    "evidence": "...SNIP..."
  }
]
```

### Second Iteration

How about only the results (`ADD` or `DUPLICATE`), `task_uid` and `title`? Better, but still caused issues.

```json
[
  {
    "event": "ADD",
    "task_uid": "2b4166e3-711b-48b3-a25c-3af6e99a057c",
    "title": "...SNIP..."
  },
  {
    "event": "DUPLICATE",
    "task_uid": "b151c29a-5176-4fdb-a42a-cf2a15ac6602",
    "title": "...SNIP..."
  }
]
```

The intent is `get_active_task` is called after `create_tasks` is called. The result looks like:

```
<active_task phase="2" status="active">
{
  "activated": true,
  "task": {
    "created_at": "2026-04-11T13:40:17.728226",
    "evidence": [ "...SNIP..." ],
    "objective": "...SNIP...",
    "phase": 2,
    "status": "active",
    "status_reason": "activated",
    "task_uid": "d768ad00-3b3c-4f84-907f-8e9716c9aa86",
    "title": "...SNIP..."
  }
}
</active_task>
```

### Third Iteration

The `title` was causing misdirection. There is enough in the title to infer instructions. The task code handles choosing the next active task, so we don't need that info in the `create_tasks` output.

Also, if we expect the model to always call `get_active_task` after `create_tasks`, how about including the active task in the `create_tasks` output?

```json
[
  {
    "event": "ADD",
    "task_uid": "2b4166e3-711b-48b3-a25c-3af6e99a057c"
  },
  {
    "event": "DUPLICATE",
    "task_uid": "b151c29a-5176-4fdb-a42a-cf2a15ac6602"
  },
  {
    "event": "ACTIVATE",
    "task": {
      "created_at": "2026-04-10T16:32:25.809231",
      "evidence": [ "...SNIP..." ],
      "objective": "...SNIP...",
      "phase": 1,
      "status": "active",
      "status_reason": "activated",
      "task_uid": "4268624c-634f-42fc-8d56-d52ce24dfcab",
      "title": "...SNIP..."
    }
  }
]
```

### Fourth Iteration

There are still problems 😕

It seemed like a good idea to output whether each task was added, or a duplicate was found. Nope. Sometimes the model would take `DUPLICATE` as an instruction to re-write the task until it wasn't a duplicate. The agent could spend several turns rewriting the same task.

UUIDs seem like a good idea. Some tools can take a UUID, such as `task_uid`, and use it to mark a specific task as done. Models will, fairly quickly, hallucinate UUIDs. Use them sparingly.

I landed on simply tells the model the tasks were created and including the active task. I had thought using well-defined JSON would be better. Models do understand JSON, but now that there is only "tasks created", it's unnecessary. Also, considering the `get_active_task` tool outputs the `<active_task>...` format, keeping the output of `create_tasks` consistent is helpful.

```
Tasks created.

<active_task phase="2" status="active">
{
  "activated": true,
  "task": {
    "created_at": "2026-04-11T13:40:17.728226",
    "evidence": [ "...SNIP..." ],
    "objective": "...SNIP...",
    "phase": 2,
    "status": "active",
    "status_reason": "activated",
    "task_uid": "d768ad00-3b3c-4f84-907f-8e9716c9aa86",
    "title": "...SNIP..."
  }
}
</active_task>
```

I haven't seem models get misdirected by this yet, large or small.

## task_done

The `task_done` tool marks the active task or one specified by `task_uid` as done. It also activates the next task. Originally the prompt instructed the model to call `task_done` then `get_active_task`. Now, `task_done`, does both and outputs the active task. This seems to work well.

```
<active_task phase="2" status="active">
{
  "activated": true,
  "closed": {
    "status": "done",
    "task_uid": "713c827c-8b86-4ad4-8d4c-50e90693ab87"
  },
  "task": {
    "created_at": "2026-04-11T13:40:17.728226",
    "evidence": [ "...SNIP..." ],
    "objective": "...SNIP...",
    "phase": 2,
    "status": "active",
    "status_reason": "activated",
    "task_uid": "d768ad00-3b3c-4f84-907f-8e9716c9aa86",
    "title": "...SNIP..."
  }
}
</active_task>
```

## null

Don't output null values, unless it is the only output. I found sometimes the model will see `null` and forget everything else and determine the tool failed. Out of all the output of the particular tool where I saw this, it locked on `null`. I added a filter to all dictionaries I output to remove null values.

## Refactoring Planning

Thinking more about the planning process, I am considering removing most of the planning and task logic out of prompts and into procedural code.

The agent will still be responsible for creating the plan and evaluating completion criteria. It will create tasks. The execution of tasks will be driven by prodecural code and new agents created for each task. The context can be made specific to the task without the cognitive load of previous actions. There is also an opportunity for parallel work across multiple agents.

Although I don't have the resources to test with frontier models, I've seen evidence from others that a large context window is detrimental to performance. That makes sense, unrelated history is kept as the model moves from task to task. Using a new agent for each task should also reduce the token usage.
