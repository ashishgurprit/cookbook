# Atlassian Engineering Practices

> Best practices from Atlassian's development culture.
> Sources: Atlassian Team Playbook, Engineering Blog

## Core Principles

### 1. Definition of Done (DoD)

A feature is NOT done until:

```markdown
## Definition of Done Checklist

### Code Complete
- [ ] Code written and self-reviewed
- [ ] Unit tests written and passing
- [ ] Integration tests passing
- [ ] No linting errors
- [ ] No security vulnerabilities

### Review Complete
- [ ] PR reviewed and approved
- [ ] All comments addressed
- [ ] CI/CD pipeline green

### Documentation Complete
- [ ] Code comments for complex logic
- [ ] API documentation updated
- [ ] README updated if needed
- [ ] Changelog entry added

### Testing Complete
- [ ] QA tested (if applicable)
- [ ] Edge cases verified
- [ ] Performance acceptable
- [ ] Accessibility checked

### Deployment Ready
- [ ] Feature flag configured (if needed)
- [ ] Monitoring/alerts set up
- [ ] Rollback plan documented
- [ ] Stakeholders notified
```

### 2. Agile Ceremonies

**Sprint Planning**
- Define sprint goal (ONE clear objective)
- Break stories into tasks (< 1 day each)
- Identify dependencies and blockers
- Commit to realistic scope

**Daily Standup (15 min max)**
```
1. What did I complete yesterday?
2. What will I work on today?
3. Any blockers?
```

**Sprint Retrospective**
```markdown
## Retro Format: 4 Ls

### Liked
- [What went well]

### Learned
- [New insights]

### Lacked
- [What was missing]

### Longed For
- [What we wish we had]

## Action Items
- [ ] [Specific improvement] - Owner
```

### 3. DACI Decision Framework

For important decisions:

| Role | Person | Responsibility |
|------|--------|----------------|
| **D**river | [Name] | Drives the decision, gathers input |
| **A**pprover | [Name] | Final say, one person only |
| **C**ontributors | [Names] | Provide input and expertise |
| **I**nformed | [Names] | Kept in the loop |

### 4. Health Monitors

Regular team health checks:

| Attribute | 🟢 Healthy | 🔴 Unhealthy |
|-----------|------------|--------------|
| **Balanced Team** | Right skills, capacity | Gaps, overloaded |
| **Shared Understanding** | Everyone aligned | Confusion |
| **Value & Metrics** | Clear success criteria | No measures |
| **Proof of Concept** | Validated approach | Unproven |
| **Velocity** | Predictable delivery | Erratic |
| **Full-Time Owner** | Dedicated lead | Part-time |
| **Dependencies** | Managed | Blocking |
| **Stakeholder Support** | Engaged | Absent |

### 5. Incident Management

**Severity Levels**
| Level | Description | Response Time |
|-------|-------------|---------------|
| SEV1 | Complete outage | Immediate |
| SEV2 | Major feature broken | < 1 hour |
| SEV3 | Minor feature broken | < 4 hours |
| SEV4 | Low impact | Next business day |

**Incident Response**
```
1. DETECT - Monitoring alerts or user reports
2. RESPOND - Acknowledge, assign incident commander
3. MITIGATE - Stop the bleeding (even if temp fix)
4. RESOLVE - Permanent fix
5. REVIEW - Blameless postmortem
```

### 6. Quality Assistance (QA)

Shift left - quality is everyone's job:

```
┌─────────────────────────────────────────────────────────────┐
│                 QUALITY ASSISTANCE MODEL                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Traditional QA          Quality Assistance                 │
│  ──────────────          ─────────────────                  │
│  QA tests at end    →    Dev writes tests                   │
│  QA finds bugs      →    Dev prevents bugs                  │
│  QA owns quality    →    Team owns quality                  │
│  QA = gatekeeper    →    QA = coach/enabler                 │
│                                                             │
│  "Quality is not a phase, it's built in"                   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 7. Code Review Guidelines

**As Author**
- Self-review first
- Keep PRs small (< 400 lines)
- Provide context in description
- Respond promptly to feedback

**As Reviewer**
- Review within 4 hours
- Be constructive, not critical
- Approve if "good enough"
- Use suggestions, not demands

**PR Template**
```markdown
## Summary
[What does this PR do?]

## Changes
- [Change 1]
- [Change 2]

## Testing
- [ ] Unit tests
- [ ] Manual testing
- [ ] Screenshots (if UI)

## Checklist
- [ ] Self-reviewed
- [ ] Tests passing
- [ ] Docs updated
```

### 8. Playbook Plays

**Pre-mortem** (Before project)
```
Imagine it's 6 months from now and the project failed.
What went wrong?

- [Risk 1] → Mitigation: [...]
- [Risk 2] → Mitigation: [...]
```

**5 Whys** (Root cause analysis)
```
Problem: Users can't log in

1. Why? → Auth service returning 500
2. Why? → Database connection timeout
3. Why? → Connection pool exhausted
4. Why? → Connections not being released
5. Why? → Missing finally block in code

ROOT CAUSE: Resource leak in auth service
```

## Quick Reference

| Practice | When to Use |
|----------|-------------|
| DoD Checklist | Every feature |
| DACI | Important decisions |
| Health Monitor | Monthly team check |
| Pre-mortem | Project kickoff |
| 5 Whys | Incident analysis |
| 4 Ls Retro | Sprint end |
