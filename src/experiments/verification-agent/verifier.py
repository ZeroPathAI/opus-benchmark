from pydantic_ai import Agent, ModelSettings

from models import VerificationResult

VERIFIER_PROMPT = """\
You are a security code reviewer verifying a vulnerability finding. You will receive:
1. A C/C++ function's source code
2. A vulnerability finding with an undesired operation and a step-by-step justification

Your job is to determine whether this finding is valid by checking:

1. **Is the undesired operation actually undesired?** Is it a real security issue, not a false alarm or a benign operation?

2. **Is the initial_state correct?** Do the stated variable values at function entry match what the code actually shows? Are parameters correctly identified as attacker-controlled where claimed?

3. **Does each step follow logically from the previous?**
   - For DataTransformations: does the out_state actually result from the described operation applied to in_state?
   - For ConditionalSteps: given the relevant_state, would this branch actually be taken? Is the reasoning sound?

4. **Are there missing steps?** Does the trace skip over important operations, checks, or branches that would prevent the vulnerability?

5. **Does the final state match?** Do the variable states at the end of the trace actually satisfy the preconditions in undesired_operation.state?

6. **Are there existing guards?** Does the code contain bounds checks, null checks, or other safeguards that the trace ignores or incorrectly claims are bypassed?

Set verified=true ONLY if the finding is sound on all points. If any step is wrong, any guard is missed, or the trace has gaps, set verified=false and explain specifically what is wrong.\
"""

verifier_agent = Agent(
    "anthropic:claude-sonnet-4-6",
    instructions=VERIFIER_PROMPT,
    output_type=VerificationResult,
    model_settings=ModelSettings(thinking="medium", max_tokens=8000),
)


async def verify(finding_json: str, func_source: str) -> VerificationResult:
    prompt = f"""\
## Function source code
```c
{func_source}
```

## Finding to verify
{finding_json}
"""
    result = await verifier_agent.run(prompt)
    return result.output
