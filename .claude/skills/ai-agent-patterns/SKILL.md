---
name: ai-agent-patterns
description: "Production patterns for building LLM-powered agents, RAG systems, and conversational AI. Use when: (1) Building LLM-powered agents with tool use, (2) Implementing RAG pipelines, (3) Designing prompt templates, (4) Managing multi-turn conversations, (5) Building knowledge graphs, (6) Orchestrating multi-agent systems."
consumes_modules:
  - agent-core
  - prompt-template-engine
  - rag-pipeline
  - text-chunker
  - dialogue-manager
  - prompt-library
  - knowledge-synthesizer
  - entity-linker
---

# AI Agent Patterns

> Production patterns for building LLM-powered agents, RAG systems, and conversational AI. Use when: building tool-use agents, implementing retrieval-augmented generation, designing prompt pipelines, managing dialogue state, synthesizing knowledge, or linking entities across corpora.

---

## Module Dependencies

| Module | What It Provides |
|--------|-----------------|
| `agent-core` | Base agent class, tool registry, LLM routing, memory management |
| `prompt-template-engine` | Variable injection, template versioning, A/B prompt testing |
| `rag-pipeline` | Vector store abstraction, embedding generation, retrieval, reranking |
| `text-chunker` | Semantic splitting, token-aware chunking, overlap management |
| `dialogue-manager` | Conversation state machine, slot filling, turn management, context tracking |
| `prompt-library` | Curated system prompts, few-shot sets, role templates |
| `knowledge-synthesizer` | Multi-source synthesis, summarization, deduplication, conflict resolution |
| `entity-linker` | Named entity extraction, relationship mapping, disambiguation |

---

## Overview

This skill provides a unified reference for building intelligent LLM-powered applications. It covers the full stack from low-level prompt engineering through high-level multi-agent orchestration. The 8 consumed modules are organized into three layers:

- **Agent Layer**: `agent-core`, `prompt-library`, `prompt-template-engine`, `dialogue-manager`
- **Retrieval Layer**: `rag-pipeline`, `text-chunker`
- **Knowledge Layer**: `knowledge-synthesizer`, `entity-linker`

---

## 1. Agent Architecture

### Agent Types Decision Matrix

| Agent Type | Complexity | Use Case | Latency | Cost |
|-----------|-----------|----------|---------|------|
| Single-turn | Low | Classification, extraction | <1s | $ |
| Tool-use | Medium | API calls, code execution | 2-10s | $$ |
| ReAct | Medium-High | Reasoning + acting loops | 5-30s | $$$ |
| Conversational | Medium | Multi-turn dialogue | 1-5s/turn | $$ |
| Multi-agent | High | Complex workflows | 30s-5min | $$$$ |

### Tool-Use Agent Setup

```python
from agent_core import Agent, ToolRegistry, ConversationManager
from agent_core.tools import BaseTool, ToolResult

class SearchTool(BaseTool):
    name = "search_docs"
    description = "Search knowledge base for relevant documents"
    parameters = {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Search query"},
            "top_k": {"type": "integer", "default": 5}
        },
        "required": ["query"]
    }

    async def execute(self, query: str, top_k: int = 5) -> ToolResult:
        results = await self.vector_store.search(query=query, top_k=top_k)
        return ToolResult(success=True, data=results)


# Register tools and create agent
registry = ToolRegistry()
registry.register(SearchTool())

agent = Agent(
    model="gpt-5.2",
    system_prompt="You are a research assistant.",
    tool_registry=registry,
    max_iterations=10
)

response = await agent.run("Find papers on transformer architectures")
```

### ReAct Loop Pattern

```python
from agent_core import Agent
from agent_core.patterns import ReActLoop

react_agent = Agent(
    model="claude-sonnet-4-5-20250929",
    pattern=ReActLoop(
        max_steps=15,
        thought_prefix="Thought:",
        action_prefix="Action:",
        observation_prefix="Observation:",
    ),
    tool_registry=registry
)

# Agent will alternate: Thought -> Action -> Observation -> Thought ...
result = await react_agent.run(
    "Compare Q1 and Q2 revenue and explain the trend"
)
```

---

## 2. RAG Pipeline

### Ingestion Pipeline

```python
from text_chunker import SemanticChunker, TokenChunker
from rag_pipeline import VectorStore, EmbeddingGenerator
from entity_linker import EntityExtractor

# Step 1: Chunk documents
chunker = SemanticChunker(
    max_tokens=512,
    overlap_tokens=50,
    similarity_threshold=0.7
)
chunks = chunker.chunk(document_text)

# Step 2: Extract entities for metadata enrichment
extractor = EntityExtractor(model="en_core_web_trf")
for chunk in chunks:
    chunk.entities = extractor.extract(chunk.text)
    chunk.metadata["entity_types"] = [e.type for e in chunk.entities]

# Step 3: Generate embeddings and store
embedder = EmbeddingGenerator(model="text-embedding-3-small")
store = VectorStore(provider="pgvector", collection="docs")

embeddings = await embedder.embed_batch([c.text for c in chunks])
await store.upsert(chunks, embeddings)
```

### Retrieval with Reranking

```python
from rag_pipeline import Retriever, Reranker

retriever = Retriever(
    vector_store=store,
    embedding_generator=embedder,
    top_k=20  # over-fetch for reranking
)

reranker = Reranker(model="cross-encoder/ms-marco-MiniLM-L-12-v2")

async def rag_query(question: str, top_k: int = 5) -> list:
    # Retrieve candidates
    candidates = await retriever.search(question)

    # Rerank for precision
    ranked = reranker.rerank(query=question, documents=candidates, top_k=top_k)

    return ranked
```

### RAG Response Generation

```python
from prompt_template_engine import TemplateEngine
from prompt_library import SystemPrompts

engine = TemplateEngine()

rag_template = engine.register(
    name="rag_answer",
    version="1.2",
    template="""Answer the question based ONLY on the provided context.
If the context doesn't contain the answer, say "I don't have enough information."

Context:
{{#each sources}}
[{{@index}}] {{this.text}}
{{/each}}

Question: {{question}}

Answer (cite sources as [n]):"""
)

async def answer_with_sources(question: str):
    sources = await rag_query(question)
    prompt = engine.render("rag_answer", {
        "question": question,
        "sources": sources
    })
    return await llm.complete(prompt)
```

---

## 3. Prompt Engineering

### Template Versioning and A/B Testing

```python
from prompt_template_engine import TemplateEngine, PromptVersioner

engine = TemplateEngine()
versioner = PromptVersioner(storage="postgres")

# Register multiple versions
engine.register(name="summarize", version="1.0",
    template="Summarize this text:\n{{text}}")
engine.register(name="summarize", version="2.0",
    template="Provide a {{style}} summary of:\n{{text}}\n\nKey points:")

# A/B test between versions
active_version = versioner.get_active("summarize", user_segment="power_users")
prompt = engine.render("summarize", {"text": content, "style": "concise"},
                       version=active_version)
```

### Prompt Library Usage

```python
from prompt_library import SystemPrompts, FewShotSets, RoleTemplates

# Load curated system prompts
system = SystemPrompts.get("research_assistant")

# Add few-shot examples for consistent output format
few_shots = FewShotSets.get("json_extraction", count=3)

# Combine with role template
role = RoleTemplates.get("analyst", domain="finance")

messages = [
    {"role": "system", "content": f"{role}\n\n{system}"},
    *few_shots.to_messages(),
    {"role": "user", "content": user_query}
]
```

---

## 4. Conversation Management

### Dialogue State Machine

```python
from dialogue_manager import DialogueManager, SlotFiller, ConversationState

dm = DialogueManager(
    states={
        "greeting": ConversationState(
            transitions={"has_intent": "slot_filling", "no_intent": "clarify"}
        ),
        "slot_filling": ConversationState(
            required_slots=["date", "location", "num_guests"],
            transitions={"all_filled": "confirm", "missing": "slot_filling"}
        ),
        "confirm": ConversationState(
            transitions={"yes": "execute", "no": "slot_filling"}
        ),
        "execute": ConversationState(terminal=True)
    },
    initial_state="greeting"
)

filler = SlotFiller(extraction_model="gpt-5.2-instant")

async def handle_turn(user_message: str, session_id: str):
    context = dm.get_context(session_id)

    # Extract slot values from user message
    extracted = await filler.extract(user_message, context.missing_slots)
    context.update_slots(extracted)

    # Transition state
    next_state = dm.transition(session_id)

    # Generate response based on current state
    if next_state == "slot_filling":
        return f"I still need: {', '.join(context.missing_slots)}"
    elif next_state == "confirm":
        return f"Let me confirm: {context.slots}. Is this correct?"
    elif next_state == "execute":
        return await execute_action(context.slots)
```

### Context Window Management

```python
from dialogue_manager import ContextTracker
from text_chunker import TokenChunker

tracker = ContextTracker(max_tokens=8000)
token_counter = TokenChunker(model="gpt-4o")

def manage_context(conversation_history: list) -> list:
    total = token_counter.count_tokens(str(conversation_history))

    if total > tracker.max_tokens:
        # Summarize older turns, keep recent ones verbatim
        old_turns = conversation_history[:-4]
        recent_turns = conversation_history[-4:]

        summary = tracker.summarize(old_turns)
        return [{"role": "system", "content": f"Previous context: {summary}"}] + recent_turns

    return conversation_history
```

---

## 5. Knowledge Synthesis

### Multi-Source Synthesis

```python
from knowledge_synthesizer import Synthesizer, ConflictResolver
from entity_linker import EntityExtractor, RelationshipMapper

synthesizer = Synthesizer()
resolver = ConflictResolver(strategy="recency_weighted")
entity_extractor = EntityExtractor()
mapper = RelationshipMapper()

async def build_knowledge_graph(documents: list):
    # Extract entities from all documents
    all_entities = []
    for doc in documents:
        entities = entity_extractor.extract(doc.text)
        relationships = mapper.map_relationships(entities)
        all_entities.extend(entities)

    # Resolve conflicting facts across sources
    resolved = resolver.resolve(all_entities)

    # Synthesize into unified knowledge base
    knowledge = synthesizer.synthesize(
        entities=resolved,
        strategy="hierarchical",
        dedup_threshold=0.85
    )
    return knowledge
```

### Entity Linking Across Corpora

```python
from entity_linker import Disambiguator

disambiguator = Disambiguator(knowledge_base="wikidata")

async def link_entities(text: str):
    entities = entity_extractor.extract(text)

    linked = []
    for entity in entities:
        # Disambiguate against known knowledge base
        match = await disambiguator.link(
            mention=entity.text,
            context=entity.surrounding_text,
            candidates_limit=5
        )
        linked.append({
            "mention": entity.text,
            "type": entity.type,
            "linked_id": match.id if match else None,
            "confidence": match.confidence if match else 0
        })

    return linked
```

---

## 6. Production Deployment

### Agent with Guardrails

```python
from agent_core import Agent
from agent_core.guardrails import InputValidator, OutputFilter, RateLimiter

agent = Agent(
    model="gpt-5.2",
    tool_registry=registry,
    guardrails=[
        InputValidator(max_length=4000, block_patterns=[r"ignore previous"]),
        OutputFilter(pii_detection=True, toxicity_threshold=0.8),
        RateLimiter(requests_per_minute=30, tokens_per_minute=50000)
    ]
)
```

### Evaluation Framework

```python
from agent_core.eval import EvalSuite, Metric

suite = EvalSuite(
    metrics=[
        Metric.ANSWER_RELEVANCE,
        Metric.FAITHFULNESS,       # Does answer match sources?
        Metric.CONTEXT_PRECISION,  # Are retrieved docs relevant?
        Metric.CONTEXT_RECALL,     # Are all needed docs retrieved?
    ]
)

results = await suite.evaluate(
    questions=test_questions,
    ground_truth=expected_answers,
    pipeline=rag_query
)
print(results.summary())
# answer_relevance: 0.89, faithfulness: 0.94, ...
```

---

## Quick Reference

| Task | Module | Key Function |
|------|--------|-------------|
| Create an agent | `agent-core` | `Agent(model, tool_registry)` |
| Register tools | `agent-core` | `ToolRegistry.register(tool)` |
| Chunk documents | `text-chunker` | `SemanticChunker.chunk(text)` |
| Generate embeddings | `rag-pipeline` | `EmbeddingGenerator.embed_batch(texts)` |
| Vector search | `rag-pipeline` | `Retriever.search(query)` |
| Rerank results | `rag-pipeline` | `Reranker.rerank(query, docs)` |
| Render prompts | `prompt-template-engine` | `TemplateEngine.render(name, vars)` |
| Get system prompts | `prompt-library` | `SystemPrompts.get(name)` |
| Manage dialogue | `dialogue-manager` | `DialogueManager.transition(session)` |
| Fill slots | `dialogue-manager` | `SlotFiller.extract(message, slots)` |
| Extract entities | `entity-linker` | `EntityExtractor.extract(text)` |
| Link to KB | `entity-linker` | `Disambiguator.link(mention, context)` |
| Synthesize knowledge | `knowledge-synthesizer` | `Synthesizer.synthesize(entities)` |
| Resolve conflicts | `knowledge-synthesizer` | `ConflictResolver.resolve(entities)` |

### Architecture Decision Tree

```
Need an LLM feature?
├── Single question/answer → Single-turn agent (agent-core)
├── Needs external data → RAG pipeline (rag-pipeline + text-chunker)
├── Multi-turn conversation → Dialogue manager (dialogue-manager)
├── Complex reasoning → ReAct agent (agent-core)
├── Knowledge consolidation → Synthesizer (knowledge-synthesizer + entity-linker)
└── Multiple cooperating agents → Multi-agent orchestration (agent-core)
```

---

# Research Update: February 2026

## Model Landscape Changes

| Provider | Latest Models | Key Changes |
|----------|--------------|-------------|
| **Anthropic** | Opus 4.6, Sonnet 4.5, Haiku 4.5 | Opus 4.6 (Feb 2026). Tool Search Tool for dynamic discovery. Programmatic Tool Calling. Structured outputs GA. Agent Skills beta. |
| **OpenAI** | GPT-5.3-Codex, GPT-5.2 (Instant/Thinking/Pro) | Assistants API sunset planned 2026 — migrate to Responses API. Video API added. GPT-4o retired Feb 13 2026. |
| **Embeddings** | `text-embedding-3-large` | Still current. No major embedding model changes. |

## Breaking Changes

- **OpenAI model retirements** (Feb 13, 2026): GPT-4o, GPT-4.1, GPT-4.1 mini, o4-mini, GPT-5 Instant, GPT-5 Thinking removed from ChatGPT.
- **Anthropic tool use**: New features — Tool Search Tool (discovers tools on-demand), Programmatic Tool Calling (code execution env), Tool Use Examples (demonstrations). Fine-grained tool streaming GA.
- **Anthropic structured outputs**: GA on all 4.5 models. No beta header required.
- **OpenAI Assistants API**: Planned sunset in 2026. Migrate to Responses API which brings all Assistants features.

## Recommended Model Selection (Feb 2026)

```python
MODEL_RECOMMENDATIONS = {
    # Best overall reasoning
    "reasoning": "claude-opus-4-6",
    # Best coding
    "coding": "gpt-5.3-codex",
    # Fast + cheap
    "fast": "claude-haiku-4-5-20251001",
    # Balanced
    "balanced": "claude-sonnet-4-5-20250929",
    # OpenAI balanced
    "openai_balanced": "gpt-5.2",
}
```
