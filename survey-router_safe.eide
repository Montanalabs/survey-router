#! Survey router — untrusted a response can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires routeSurvey — the survey router sink
#! @effect io
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant routeSurvey

type SurveyKind = Nps | Csat | Ces
type Decision = RouteSurvey(SurveyKind) | DropSurvey

let raw = fetch<web>  # UNTRUSTED a response — tainted
quarantined { let d = extract<Decision>(raw) }  # only a fixed Decision (payloads too) crosses
privileged { routeSurvey(d) }  # act on the trusted decision only
