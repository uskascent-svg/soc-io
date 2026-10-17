# SOC-IO analyst triage runbook

This runbook is for the offline prototype and synthetic/authorized lab data. It is not a substitute for your organization's incident-response plan.

## 1. Prepare evidence
- Confirm you are authorized to analyze the data.
- Preserve the original input file and record its source, collection window, host/time zone, and collector version.
- Work on a copy. Do not paste sensitive event data into public issues.
- Validate system clocks and time zones before correlating events.

## 2. Run the triage
```bash
PYTHONPATH=src python -m socio.cli examples/events.jsonl --json report.json
``
Record the commit SHA, command, input filename, and report filename. Treat parser warnings as a data-quality issue requiring review.

## 3. Review each alert
1. Read the rule ID, severity label, summary, and linked event IDs.
2. Confirm the original source event and surrounding timeline.
3. Check host, account, source IP, process lineage, and other relevant telemetry.
4. Compare against approved administrative activity and known maintenance windows.
5. Document supporting and contradictory evidence.
6. Escalate according to your organization's incident-response policy.

## 4. Decide and document
- **True positive:** evidence supports the behavior described by the rule.
- **False positive:** evidence shows the activity is benign or expected.
- **Needs investigation:** available evidence is insufficient.
- **Data-quality issue:** missing, malformed, delayed, or contradictory telemetry prevents assessment.

Do not treat a severity label as probability or proof. Absence of an alert does not mean a system is safe.

## 5. Response actions
SOC-IO does not isolate hosts, disable accounts, delete files, or execute response commands. Any containment or remediation must be separately authorized and carried out under an approved playbook by an authorized operator.

## 6. Case notes template
- Case/reference:
- Analyst:
- Review date/time (include timezone):
- Input source and collection window:
- SOC-IO commit/version:
- Rule ID and alert ID:
- Affected host/account:
- Supporting evidence:
- Contradictory evidence:
- Disposition and rationale:
- Follow-up owner:
- Approval and actions taken outside SOC-IO:
