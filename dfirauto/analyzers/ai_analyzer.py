"""AI narrative generation for DFIR triage reports.

Provider-agnostic: whichever API key is present in the environment is used
automatically. If more than one is set, priority is:
ANTHROPIC_API_KEY > GEMINI_API_KEY > OPENAI_API_KEY.
"""

from __future__ import annotations

import asyncio
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dfirauto.types.artifacts import TriageReport


async def _call_anthropic(prompt: str, api_key: str) -> str:
    import anthropic
    client = anthropic.Anthropic(api_key=api_key)
    loop = asyncio.get_event_loop()
    response = await loop.run_in_executor(
        None,
        lambda: client.messages.create(
            model="claude-3-5-haiku-20241022",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        ),
    )
    return response.content[0].text.strip()


async def _call_gemini(prompt: str, api_key: str) -> str:
    import google.generativeai as genai
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-1.5-flash")
    loop = asyncio.get_event_loop()
    response = await loop.run_in_executor(None, lambda: model.generate_content(prompt))
    return response.text.strip()


async def _call_openai(prompt: str, api_key: str) -> str:
    import openai
    client = openai.OpenAI(api_key=api_key)
    loop = asyncio.get_event_loop()
    response = await loop.run_in_executor(
        None,
        lambda: client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
        ),
    )
    return response.choices[0].message.content.strip()


async def _call_ai(prompt: str) -> str:
    """
    Dispatch to whichever AI provider has an API key configured in the
    environment. Priority when more than one is set:
    ANTHROPIC_API_KEY > GEMINI_API_KEY > OPENAI_API_KEY.

    Never raises — returns "" if no key is set or the call fails, so callers
    can degrade gracefully and keep working without AI.
    """
    providers = (
        (os.getenv("ANTHROPIC_API_KEY"), _call_anthropic),
        (os.getenv("GEMINI_API_KEY"), _call_gemini),
        (os.getenv("OPENAI_API_KEY"), _call_openai),
    )
    for api_key, call_fn in providers:
        if not api_key:
            continue
        try:
            return await call_fn(prompt, api_key)
        except Exception:
            return ""
    return ""


async def analyze_triage(report: "TriageReport") -> None:
    """Generate AI incident narrative, IOC summary, and recommendations."""
    artifacts = report.sorted_artifacts()
    if not artifacts:
        return

    # Build evidence summary
    critical = [a for a in artifacts if a.severity.value == "critical"]
    high = [a for a in artifacts if a.severity.value == "high"]
    summary = report.summary

    evidence_lines = []
    for a in artifacts[:25]:
        line = f"[{a.severity.value.upper()}] [{a.artifact_type.value}] {a.description[:120]}"
        if a.mitre_techniques:
            line += f" | MITRE: {', '.join(a.mitre_techniques[:3])}"
        evidence_lines.append(line)

    all_iocs = list({ioc for a in artifacts for ioc in a.iocs})[:20]
    all_mitre = list({t for a in artifacts for t in a.mitre_techniques})[:15]
    all_tags = list({t for a in artifacts for t in a.tags})[:15]

    prompt = f"""You are a senior DFIR analyst. Analyze this forensic triage report and provide an incident assessment.

Host: {report.hostname}
Triage started: {report.started_at.strftime('%Y-%m-%d %H:%M UTC')}
Duration: {report.duration_seconds:.0f}s

Findings Summary:
- Total artifacts: {summary['total_artifacts']}
- Critical: {summary['critical']}, High: {summary['high']}, Medium: {summary['medium']}
- Timeline events: {summary['timeline_events']}

Critical findings:
{chr(10).join(f'  {e}' for e in evidence_lines[:10])}

MITRE techniques detected: {', '.join(all_mitre)}
Tags: {', '.join(all_tags)}
IOCs found: {', '.join(all_iocs) if all_iocs else 'none'}

Provide:
1. INCIDENT_NARRATIVE: 3-4 sentence incident timeline reconstruction — what likely happened, in what order, and what the attacker's goal appears to be
2. THREAT_ASSESSMENT: Overall severity (CRITICAL/HIGH/MEDIUM) with one-sentence rationale
3. IOC_SUMMARY: Key indicators of compromise to add to blocklists
4. RECOMMENDATIONS: 4 specific containment/remediation actions

Format exactly:
INCIDENT_NARRATIVE: <narrative>
THREAT_ASSESSMENT: <SEVERITY> — <one sentence rationale>
IOC_SUMMARY: <comma-separated IOCs or "none identified">
RECOMMENDATIONS:
- <action 1>
- <action 2>
- <action 3>
- <action 4>"""

    response = await _call_ai(prompt)
    if not response:
        return

    narrative = ""
    ioc_summary = ""
    recs: list[str] = []
    in_recs = False

    for line in response.splitlines():
        line = line.strip()
        if line.startswith("INCIDENT_NARRATIVE:"):
            narrative = line[19:].strip()
            in_recs = False
        elif line.startswith("THREAT_ASSESSMENT:"):
            # Append to narrative
            assessment = line[18:].strip()
            if assessment:
                narrative = (narrative + "\n\n" + assessment).strip()
            in_recs = False
        elif line.startswith("IOC_SUMMARY:"):
            ioc_summary = line[12:].strip()
            in_recs = False
        elif line.startswith("RECOMMENDATIONS:"):
            in_recs = True
        elif in_recs and line.startswith("- "):
            recs.append(line[2:].strip())
        elif narrative and not in_recs and line and not line.startswith(("INCIDENT", "THREAT", "IOC", "RECOMMEND")):
            narrative += " " + line

    if narrative:
        report.ai_narrative = narrative
    if ioc_summary and ioc_summary.lower() != "none identified":
        report.ai_ioc_summary = ioc_summary
    if recs:
        report.recommendations = recs[:4]
