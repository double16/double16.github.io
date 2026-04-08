---
layout: post
title:  "LLM Tool Batching"
date:   2026-04-08
categories:
- ai
comments: true
---

I discovered while working on [Cyber-AutoAgent-ng](https://github.com/double16/Cyber-AutoAgent-ng), that LLMs perform better invoking tools with arguments as a batch rather than instructing the LLM to loop over data to make tool calls.

Code snippets are from commit [7e4068b](https://github.com/double16/Cyber-AutoAgent-ng/tree/7e4068b0f664227ac4f251a288adbed98afa4ec1). Tools refer to the Strands SDK, which are defined using Python functions (or modules) and passed to the model.

This is the `create_tasks` tool definition. It accepts a list of `TaskCreate` objects. The intent of a task is to capture narrowly scoped work. Many tasks can be inferred from one tool output, such as a spider, fuzzer or vulnerability scanner. I've seen 50 before.

```python
@dataclass
class TaskCreate:
    title: str
    objective: str
    phase: Optional[int]
    status: TaskStatus
    evidence: Any = field(default_factory=list)

@tool
def create_tasks(tasks: List[TaskCreate]) -> str:
    # SNIP
```

I started with accepting a single `TaskCreate` object.

```python
@tool
def create_tasks(task: TaskCreate) -> str:
    # SNIP

```

The system prompt instructed the LLM to loop over the inferred tasks and invoke the tool. This did not work well. The LLM would create a few, two to four, then start processing a task. Different models behaved differently, but none I observed did what I wanted. It makes sense. The full conversation gives a stronger signal to find and exploit vulnerabilities rather than finish creating tasks.

Once I added the batching, the LLM almost always creates the tasks I expect. One caveat is the input schema. It's a list of objects, but the LLM sometimes sends a JSON **string** of a list. Sometimes a **dictionary** of one object. There will be a failure message and the LLM usually re-sends the correct format. I think the best approach is for the function to coerce the input as best it can, but then the input schema is not specific. I'm almost ready to patch the Strands tool handler to look for common failure cases and coerce the input.

The system prompt needs to specify batching. Here are some snippets from the version 0.8.0 system prompt:

```
## Create tasks
Use batch creation:
- `create_tasks(tasks=[{title, objective, evidence:[...], phase, status}, ...])`

...SNIP...

1) Enumerate candidate threads from: memory_context, plan, existing tasks, findings/observations, fresh tool output.
2) Create 1 task per thread (do not merge unrelated threads). Prefer full capture of all implied candidates.

...SNIP...

Fan-out rules (MUST create multiple tasks when lists exist):
- Endpoints/paths → ≥1 task per set of parameterized paths.
- Params/injection points → ≥1 task per parameter/point.
- Host → ≥1 task per host.
- Tech/Version → ≥1 task per tech/version.
- Multiple vuln classes → ≥1 task per class per endpoint/path/param/host.
- Multiple auth flows/roles/resources → ≥1 task per flow/role/resource.
```

For the `create_tasks` use case, there is more prompt than I like. However, when I try to shorten it the LLM fails to create enough tasks, or the task objective is too broad or covers multiple vulnerabilities and endpoints. C'est la vie.

In general, use batching with your LLM tools unless you have a compelling reason otherwise.
