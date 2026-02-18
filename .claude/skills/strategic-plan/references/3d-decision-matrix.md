# 3D Decision Matrix Reference

Quick reference for the three-dimensional decision framework.

## The Three Dimensions

```
WHO (C-Suite) × HOW (Thinking Hats) × WHAT/WHEN (Framework)
```

---

## Dimension 1: C-Suite Perspectives

| Role | Focus | Key Questions |
|------|-------|---------------|
| **CEO** | Vision, Strategy, Culture | Does this align with our mission? |
| **CTO** | Architecture, Engineering | Is this technically sound and scalable? |
| **CPO** | Product, UX, Users | Does this serve user needs? |
| **CFO** | Resources, ROI, Efficiency | Is this cost-effective? |
| **COO** | Operations, Execution | Can we deliver this reliably? |
| **CRO** | Adoption, Value, Success | Will users adopt and succeed? |

---

## Dimension 2: Six Thinking Hats

| Hat | Focus | Role-Pairing |
|-----|-------|--------------|
| ⚪ **White** | Facts, Data | CTO (specs), CPO (research), CFO (data) |
| 🔴 **Red** | Emotions, Intuition | CEO (strategic feel), CPO (empathy) |
| ⚫ **Black** | Risks, Caution | CTO (tech risks), COO (ops risks), CFO (budget) |
| 🟡 **Yellow** | Benefits, Value | CEO (strategic value), CPO (user value) |
| 🟢 **Green** | Creativity, Alternatives | CTO (tech options), CPO (UX options) |
| 🔵 **Blue** | Process, Control | COO (execution), CEO (governance) |

### Common Hat Sequences

**Trapdoor Decisions (full):**
🔵 → ⚪ → 🟢 → 🟡 → ⚫ → 🔴 → 🔵

**Creative Decisions:**
⚪ → 🟢 → 🟡 → ⚫ → 🔴

**Risk Assessment:**
⚪ → ⚫ → 🟢 → 🟡

**Quick Tactical:**
⚪ → 🔴

---

## Dimension 3: Decision Frameworks

### SPADE Framework (Gokul Rajaram)

**S - Setting:** What decision? Why important? What context?
**P - People:** Who is Responsible, Approver, Consultant, Informed?
**A - Alternatives:** List 3-5 options with pros/cons
**D - Decide:** Select with clear rationale
**E - Explain:** Document and communicate

### Stripe Trapdoor Principle (Claire Hughes Johnson)

**One-way door decisions require more deliberation:**
- Can you reverse this easily?
- What's the cost to reverse?
- What's locked in after this choice?

### Amazon Disagree & Commit

- Encourage vigorous debate during deliberation
- Once decided, commit fully without undermining
- "I disagree but will commit" > "I told you so"

---

## Decision Classification Matrix

```
                    REVERSIBILITY
          ┌─────────────────┬─────────────────┐
          │   TWO-WAY DOOR  │   ONE-WAY DOOR  │
┌─────────┼─────────────────┼─────────────────┤
│  HIGH   │  HIGH-STAKES    │    TRAPDOOR     │
│         │  ─────────────  │   ───────────   │
│         │  Quick SPADE    │  Full SPADE +   │
IMPORTANCE│  Key Hats       │  All Hats +     │
│         │                 │  Commitment     │
├─────────┼─────────────────┼─────────────────┤
│  LOW    │      YOLO       │     VERIFY      │
│         │  ─────────────  │   ───────────   │
│         │  Just do it     │  Quick check    │
│         │                 │  then go        │
└─────────┴─────────────────┴─────────────────┘
```

### Trapdoor Examples
- API naming and structure
- Database schema design
- Framework selection
- Public interface contracts
- Architectural patterns
- Data formats and protocols

### High-Stakes Examples
- Implementation approach
- Internal tool selection
- Process improvements
- Feature prioritization
- Technical debt tradeoffs

### Low-Stakes Examples
- Code formatting
- Variable naming
- File organization
- Internal documentation structure
- Asset selection

---

## Quick Decision Guide

### Step 1: Classify
Ask: Is it reversible? Is it important?

### Step 2: Select Process

**TRAPDOOR → Full SPADE**
- All 6 thinking hats
- 4+ C-Suite perspectives
- Document everything
- Commitment meeting

**HIGH-STAKES → Quick SPADE**
- White, Yellow, Black, Red hats
- 2 C-Suite perspectives
- Brief documentation

**LOW-STAKES → Just Decide**
- White hat (facts)
- Red hat (gut check)
- Move forward

### Step 3: Execute

Apply selected process consistently.

### Step 4: Commit

No second-guessing after decision.

---

## Hat + Role Power Combinations

**Technical Decisions:**
- ⚪ White + CTO = Technical facts and specs
- ⚫ Black + CTO = Technical risks and debt
- 🟢 Green + CTO = Alternative architectures

**Product Decisions:**
- ⚪ White + CPO = User research and data
- 🔴 Red + CPO = User empathy and intuition
- 🟡 Yellow + CPO = User value and benefits

**Strategic Decisions:**
- 🔴 Red + CEO = Strategic gut check
- 🟡 Yellow + CEO = Strategic value alignment
- 🔵 Blue + CEO = Governance and authority

**Operational Decisions:**
- ⚫ Black + COO = Operational risks
- 🔵 Blue + COO = Execution planning
- ⚪ White + CFO = Resource constraints

---

## Common Mistakes to Avoid

1. **Over-processing simple decisions** - Use the matrix!
2. **Under-processing trapdoors** - Take time on irreversible choices
3. **Skipping Black Hat** - Always identify risks
4. **Solo perspective** - Always use 2+ roles
5. **Analysis paralysis** - Set deadlines, then decide
6. **Failure to commit** - Disagree during, commit after
7. **Forgetting to document** - Future you needs context

---

## References

- **Six Thinking Hats**: Edward de Bono (1985)
- **SPADE Framework**: Gokul Rajaram, Square/DoorDash
- **Stripe Operating Principles**: Claire Hughes Johnson, *Scaling People* (2023)
- **Amazon Leadership Principles**: amazon.jobs/principles
