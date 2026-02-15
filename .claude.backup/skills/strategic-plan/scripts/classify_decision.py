#!/usr/bin/env python3
"""
Decision Classifier for 3D Strategic Planning

Helps classify decisions to determine the appropriate decision-making process.
"""

import sys
import json
import io
from typing import Dict, List, Tuple

# Set UTF-8 encoding for Windows console
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')


# Decision classification keywords
TRAPDOOR_INDICATORS = {
    'name', 'naming', 'api', 'interface', 'public', 'contract', 'architecture',
    'framework', 'database', 'schema', 'protocol', 'format', 'standard'
}

HIGH_IMPORTANCE_INDICATORS = {
    'architecture', 'scalability', 'security', 'user experience', 'performance',
    'data model', 'integration', 'migration', 'deployment', 'infrastructure'
}

LOW_REVERSIBILITY_INDICATORS = {
    'database', 'api', 'contract', 'public interface', 'data format',
    'architecture', 'migration', 'framework', 'protocol', 'standard',
    'naming', 'versioning'
}

LOW_IMPORTANCE_INDICATORS = {
    'formatting', 'style', 'comment', 'variable name', 'file organization',
    'internal tool', 'logging', 'debug', 'local', 'temporary'
}


def classify_decision(decision_description: str) -> Dict:
    """
    Classify a decision based on its description.

    Returns:
        {
            'type': 'TRAPDOOR' | 'HIGH-STAKES' | 'LOW-STAKES' | 'YOLO',
            'importance': 'HIGH' | 'LOW',
            'reversibility': 'ONE-WAY' | 'TWO-WAY',
            'process': str,
            'hat_sequence': List[str],
            'perspectives': List[str],
            'confidence': float
        }
    """
    desc_lower = decision_description.lower()

    # Determine importance
    importance_score = 0
    for indicator in HIGH_IMPORTANCE_INDICATORS:
        if indicator in desc_lower:
            importance_score += 1

    for indicator in LOW_IMPORTANCE_INDICATORS:
        if indicator in desc_lower:
            importance_score -= 1

    importance = 'HIGH' if importance_score > 0 else 'LOW'

    # Determine reversibility
    reversibility_score = 0
    for indicator in LOW_REVERSIBILITY_INDICATORS:
        if indicator in desc_lower:
            reversibility_score += 1

    reversibility = 'ONE-WAY' if reversibility_score > 0 else 'TWO-WAY'

    # Check for trapdoor indicators
    is_trapdoor = any(indicator in desc_lower for indicator in TRAPDOOR_INDICATORS)

    # Determine decision type
    if is_trapdoor or (importance == 'HIGH' and reversibility == 'ONE-WAY'):
        decision_type = 'TRAPDOOR'
        process = 'Full SPADE with Commitment Meeting'
        hat_sequence = ['BLUE', 'WHITE', 'GREEN', 'YELLOW', 'BLACK', 'RED', 'BLUE']
        perspectives = ['CEO', 'CTO', 'CPO', 'CRO']

    elif importance == 'HIGH' and reversibility == 'TWO-WAY':
        decision_type = 'HIGH-STAKES'
        process = 'Quick SPADE'
        hat_sequence = ['WHITE', 'GREEN', 'YELLOW', 'BLACK', 'RED']
        perspectives = ['CTO', 'CPO']

    elif importance == 'LOW' and reversibility == 'ONE-WAY':
        decision_type = 'VERIFY'
        process = 'Quick Check then Go'
        hat_sequence = ['WHITE', 'BLACK']
        perspectives = ['CTO']

    else:  # LOW importance, TWO-WAY
        decision_type = 'YOLO'
        process = 'Just Do It'
        hat_sequence = ['WHITE']
        perspectives = ['owner']

    # Calculate confidence based on keyword matches
    total_indicators = (
        len([i for i in TRAPDOOR_INDICATORS if i in desc_lower]) +
        len([i for i in HIGH_IMPORTANCE_INDICATORS if i in desc_lower]) +
        len([i for i in LOW_REVERSIBILITY_INDICATORS if i in desc_lower])
    )

    confidence = min(0.5 + (total_indicators * 0.1), 0.95)

    return {
        'type': decision_type,
        'importance': importance,
        'reversibility': reversibility,
        'process': process,
        'hat_sequence': hat_sequence,
        'perspectives': perspectives,
        'confidence': confidence
    }


def get_recommended_questions(decision_type: str) -> List[str]:
    """Get recommended questions based on decision type."""

    questions = {
        'TRAPDOOR': [
            "Is this decision truly irreversible or just expensive to reverse?",
            "Have we consulted all relevant C-Suite perspectives?",
            "What are the long-term implications (3-5 years)?",
            "Are we considering this strategically, not just tactically?",
            "Do we have sufficient data to make this call?",
        ],
        'HIGH-STAKES': [
            "What are the 2-3 main alternatives?",
            "What are the key risks and benefits of each?",
            "Which perspective (CTO/CPO/CFO) matters most here?",
            "Can we prototype or test before full commitment?",
        ],
        'VERIFY': [
            "What's the worst-case scenario if this goes wrong?",
            "Is there a standard or best practice we should follow?",
            "Quick sanity check: does this make sense?",
        ],
        'YOLO': [
            "Do we have the basic facts?",
            "Is there any obvious blocker?",
            "Can we just try it and iterate?",
        ]
    }

    return questions.get(decision_type, [])


def print_classification_report(decision: str, classification: Dict):
    """Print a formatted classification report."""

    print("\n" + "="*70)
    print("  DECISION CLASSIFICATION REPORT")
    print("="*70)
    print(f"\nDecision: {decision}")
    print(f"\n{'─'*70}")
    print(f"  Type:          {classification['type']}")
    print(f"  Importance:    {classification['importance']}")
    print(f"  Reversibility: {classification['reversibility']}")
    print(f"  Confidence:    {classification['confidence']:.0%}")
    print(f"{'─'*70}")

    print(f"\n📋 Recommended Process: {classification['process']}")

    print(f"\n👥 C-Suite Perspectives:")
    for perspective in classification['perspectives']:
        print(f"   • {perspective}")

    print(f"\n🎩 Thinking Hat Sequence:")
    hat_symbols = {
        'BLUE': '🔵',
        'WHITE': '⚪',
        'RED': '🔴',
        'BLACK': '⚫',
        'YELLOW': '🟡',
        'GREEN': '🟢'
    }
    hat_flow = ' → '.join([f"{hat_symbols.get(hat, '•')} {hat}" for hat in classification['hat_sequence']])
    print(f"   {hat_flow}")

    questions = get_recommended_questions(classification['type'])
    if questions:
        print(f"\n💡 Key Questions to Consider:")
        for i, question in enumerate(questions, 1):
            print(f"   {i}. {question}")

    print(f"\n{'='*70}\n")


def print_decision_matrix():
    """Print the decision classification matrix."""

    matrix = """
                        REVERSIBILITY
              ┌─────────────────┬─────────────────┐
              │   TWO-WAY DOOR  │   ONE-WAY DOOR  │
              │   (Reversible)  │  (Irreversible) │
    ┌─────────┼─────────────────┼─────────────────┤
    │         │                 │                 │
    │  HIGH   │  HIGH-STAKES    │    TRAPDOOR     │
    │         │  ─────────────  │   ───────────   │
IMPORTANCE    │  Quick SPADE    │  Full SPADE +   │
    │         │  Key Hats       │  All Hats +     │
    │         │                 │  Commitment     │
    ├─────────┼─────────────────┼─────────────────┤
    │         │                 │                 │
    │  LOW    │      YOLO       │     VERIFY      │
    │         │  ─────────────  │   ───────────   │
    │         │  Just do it     │  Quick check    │
    │         │                 │  then go        │
    └─────────┴─────────────────┴─────────────────┘
    """

    print(matrix)


def main():
    """Main entry point."""

    if len(sys.argv) < 2:
        print("Usage: python classify_decision.py \"decision description\"")
        print("\nExample:")
        print('  python classify_decision.py "What should we name our new API endpoint?"')
        print("\nOptions:")
        print("  --matrix    Show the decision classification matrix")
        print("  --json      Output as JSON")
        sys.exit(1)

    # Handle flags
    if '--matrix' in sys.argv:
        print_decision_matrix()
        sys.exit(0)

    decision_description = ' '.join([arg for arg in sys.argv[1:] if not arg.startswith('--')])

    classification = classify_decision(decision_description)

    if '--json' in sys.argv:
        print(json.dumps(classification, indent=2))
    else:
        print_classification_report(decision_description, classification)

        # Print matrix reference
        print("Decision Matrix Reference:")
        print_decision_matrix()


if __name__ == '__main__':
    main()
