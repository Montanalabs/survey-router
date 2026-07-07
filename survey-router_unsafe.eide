#! VULNERABLE survey-router — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant routeSurvey

let raw = fetch<web>
privileged { routeSurvey(raw) }  # tainted -> tool: REJECTED
