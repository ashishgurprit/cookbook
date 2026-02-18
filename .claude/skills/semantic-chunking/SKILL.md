---
name: semantic-chunking
description: "Intelligent text chunking for LLM/RAG applications with context preservation and semantic boundaries. Use when: (1) Building RAG (Retrieval Augmented Generation) systems, (2) Processing long documents for LLM analysis, (3) Creating embeddings for vector search, (4) Splitting text while maintaining context, (5) Document Q&A systems. Triggers on 'semantic chunking', 'text splitting', 'RAG chunking', 'document chunking', or LLM text processing."
license: Proprietary
---

# Semantic Chunking System

Intelligent text splitting for LLM and RAG applications with context preservation, semantic boundaries, and metadata tracking.

## Quick Reference: Chunking Strategies

| Strategy | Best For | Chunk Size | Overlap | Pros | Cons |
|----------|----------|------------|---------|------|------|
| **Semantic** | General docs | Variable (100-500 words) | 10-20% | Preserves meaning | Slower processing |
| **Sentence** | Clean prose | Variable (200-400 words) | 1-2 sentences | Clean boundaries | May break context |
| **Paragraph** | Structured docs | Variable (100-300 words) | 1 paragraph | Natural breaks | Uneven sizes |
| **Fixed-Size** | Code, data | Fixed (512-1024 tokens) | 10-20% | Predictable | Cuts mid-sentence |
| **Recursive** | Mixed content | Variable (100-500 words) | Adaptive | Flexible | Complex logic |
| **Hybrid** | Production RAG | Variable (200-600 words) | Smart overlap | Best quality | More complex |

---

# WHY SEMANTIC CHUNKING?

## The Problem with Naive Chunking

```python
# ❌ BAD: Fixed character split
text = "The mitochondria is the powerhouse of the cell. It produces ATP..."
chunks = [text[i:i+500] for i in range(0, len(text), 500)]
# Result: "...powerhouse of the ce" and "ll. It produces ATP..."
# Broken mid-word, lost context!
```

## The Semantic Chunking Solution

```python
# ✓ GOOD: Semantic boundary detection
chunks = semantic_chunker.chunk(text)
# Result:
# Chunk 1: "The mitochondria is the powerhouse of the cell. It produces ATP..."
# Chunk 2: "Mitochondria have their own DNA, separate from nuclear DNA..."
# Clean semantic boundaries, context preserved!
```

---

# CHUNKING STRATEGIES

## Strategy 1: Semantic Chunking (Recommended)

```python
from langchain.text_splitter import RecursiveCharacterTextSplitter

class SemanticChunker:
    """Split text at semantic boundaries"""

    def __init__(self, chunk_size=500, chunk_overlap=50):
        self.splitter = RecursiveCharacterTextSplitter(
            chunk_size=chunk_size,
            chunk_overlap=chunk_overlap,
            separators=[
                "\n\n",      # Paragraphs (highest priority)
                "\n",        # Lines
                ". ",        # Sentences
                ", ",        # Clauses
                " ",         # Words
                ""           # Characters (last resort)
            ],
            length_function=len
        )

    def chunk(self, text: str) -> List[str]:
        return self.splitter.split_text(text)
```

**When to use:**
- General-purpose document processing
- Blog posts, articles, documentation
- Need context preservation
- Quality > speed

## Strategy 2: Sentence-Based Chunking

```python
import nltk
from typing import List

class SentenceChunker:
    """Group sentences into chunks"""

    def __init__(self, target_words=300, overlap_sentences=2):
        self.target_words = target_words
        self.overlap_sentences = overlap_sentences
        nltk.download('punkt', quiet=True)

    def chunk(self, text: str) -> List[str]:
        sentences = nltk.sent_tokenize(text)
        chunks = []
        current_chunk = []
        current_words = 0

        for sentence in sentences:
            words = len(sentence.split())

            if current_words + words > self.target_words and current_chunk:
                # Save chunk
                chunks.append(' '.join(current_chunk))

                # Keep last N sentences for overlap
                current_chunk = current_chunk[-self.overlap_sentences:]
                current_words = sum(len(s.split()) for s in current_chunk)

            current_chunk.append(sentence)
            current_words += words

        # Add remaining
        if current_chunk:
            chunks.append(' '.join(current_chunk))

        return chunks
```

**When to use:**
- Clean, well-written prose
- News articles, stories
- Need grammatically complete chunks
- Sentence-level precision important

## Strategy 3: Fixed-Token Chunking

```python
import tiktoken

class TokenChunker:
    """Split by token count (for LLM context windows)"""

    def __init__(self, model="gpt-3.5-turbo", chunk_tokens=512, overlap_tokens=50):
        self.encoding = tiktoken.encoding_for_model(model)
        self.chunk_tokens = chunk_tokens
        self.overlap_tokens = overlap_tokens

    def chunk(self, text: str) -> List[str]:
        tokens = self.encoding.encode(text)
        chunks = []

        for i in range(0, len(tokens), self.chunk_tokens - self.overlap_tokens):
            chunk_tokens = tokens[i:i + self.chunk_tokens]
            chunk_text = self.encoding.decode(chunk_tokens)
            chunks.append(chunk_text)

        return chunks
```

**When to use:**
- Precise token budget requirements
- Working with specific LLM context windows
- Code or structured data
- Need exact token counts

## Strategy 4: Hybrid Semantic + Token Chunking (Production RAG)

```python
class HybridChunker:
    """Combine semantic boundaries with token limits"""

    def __init__(self, max_tokens=500, overlap_percent=0.15, model="gpt-3.5-turbo"):
        self.max_tokens = max_tokens
        self.overlap_tokens = int(max_tokens * overlap_percent)
        self.encoding = tiktoken.encoding_for_model(model)

    def chunk(self, text: str) -> List[Dict]:
        """Returns chunks with metadata"""
        # First: Split by semantic boundaries
        paragraphs = text.split('\n\n')

        chunks = []
        current_chunk = []
        current_tokens = 0

        for para in paragraphs:
            para_tokens = len(self.encoding.encode(para))

            # If paragraph alone exceeds max, split it
            if para_tokens > self.max_tokens:
                # Save current chunk if exists
                if current_chunk:
                    chunks.append(self._make_chunk(current_chunk, chunks))
                    current_chunk = []
                    current_tokens = 0

                # Split large paragraph by sentences
                sentences = nltk.sent_tokenize(para)
                for sent in sentences:
                    sent_tokens = len(self.encoding.encode(sent))

                    if current_tokens + sent_tokens > self.max_tokens:
                        chunks.append(self._make_chunk(current_chunk, chunks))
                        # Overlap: Keep last sentence
                        current_chunk = current_chunk[-1:] if current_chunk else []
                        current_tokens = len(self.encoding.encode(' '.join(current_chunk)))

                    current_chunk.append(sent)
                    current_tokens += sent_tokens

            # Add paragraph to current chunk
            elif current_tokens + para_tokens > self.max_tokens:
                chunks.append(self._make_chunk(current_chunk, chunks))
                # Overlap: Keep last paragraph
                current_chunk = [paragraphs[-1]] if current_chunk else []
                current_tokens = len(self.encoding.encode(current_chunk[0]))
                current_chunk.append(para)
                current_tokens += para_tokens

            else:
                current_chunk.append(para)
                current_tokens += para_tokens

        # Add final chunk
        if current_chunk:
            chunks.append(self._make_chunk(current_chunk, chunks))

        return chunks

    def _make_chunk(self, text_parts: List[str], existing_chunks: List) -> Dict:
        text = '\n\n'.join(text_parts)
        return {
            'text': text,
            'tokens': len(self.encoding.encode(text)),
            'chunk_id': len(existing_chunks),
            'char_count': len(text),
            'metadata': {
                'previous_chunk': existing_chunks[-1]['text'][:100] if existing_chunks else None,
                'position': len(existing_chunks)
            }
        }
```

**When to use:**
- Production RAG systems
- Need both quality and token control
- Complex documents
- Best retrieval accuracy

---

# ADVANCED FEATURES

## Feature 1: Metadata Preservation

```python
@dataclass
class Chunk:
    text: str
    chunk_id: int
    start_char: int
    end_char: int
    tokens: int
    metadata: Dict[str, Any]

class MetadataPreservingChunker:
    """Preserve document structure metadata"""

    def chunk_with_metadata(self, text: str, document_metadata: Dict) -> List[Chunk]:
        chunks = []
        current_pos = 0

        for i, chunk_text in enumerate(self._split_text(text)):
            chunk = Chunk(
                text=chunk_text,
                chunk_id=i,
                start_char=current_pos,
                end_char=current_pos + len(chunk_text),
                tokens=self._count_tokens(chunk_text),
                metadata={
                    **document_metadata,  # Document-level metadata
                    'section': self._detect_section(chunk_text),
                    'has_code': '```' in chunk_text,
                    'has_table': '|' in chunk_text,
                    'heading_level': self._detect_heading(chunk_text)
                }
            )
            chunks.append(chunk)
            current_pos += len(chunk_text)

        return chunks
```

## Feature 2: Smart Overlap with Context Window

```python
class ContextAwareChunker:
    """Include context from surrounding chunks"""

    def chunk_with_context(
        self,
        text: str,
        context_before: int = 100,
        context_after: int = 100
    ) -> List[Dict]:
        """Each chunk includes surrounding context"""

        base_chunks = self._split_text(text)
        chunks_with_context = []

        for i, chunk in enumerate(base_chunks):
            # Get context
            before = base_chunks[i-1][-context_before:] if i > 0 else ""
            after = base_chunks[i+1][:context_after] if i < len(base_chunks)-1 else ""

            chunks_with_context.append({
                'main_content': chunk,
                'context_before': before,
                'context_after': after,
                'full_chunk': f"{before} {chunk} {after}".strip()
            })

        return chunks_with_context
```

## Feature 3: Hierarchical Chunking

```python
class HierarchicalChunker:
    """Create parent-child chunk relationships"""

    def chunk_hierarchical(self, text: str) -> Dict:
        """Returns tree of chunks"""

        # Level 1: Sections (by headings)
        sections = self._split_by_headings(text)

        hierarchy = {
            'document': text,
            'sections': []
        }

        for section in sections:
            section_node = {
                'text': section['text'],
                'heading': section['heading'],
                'paragraphs': []
            }

            # Level 2: Paragraphs
            paragraphs = section['text'].split('\n\n')

            for para in paragraphs:
                para_node = {
                    'text': para,
                    'sentences': nltk.sent_tokenize(para)
                }
                section_node['paragraphs'].append(para_node)

            hierarchy['sections'].append(section_node)

        return hierarchy
```

---

# RAG INTEGRATION

## Embedding and Indexing

```python
from openai import OpenAI
import chromadb

class RAGChunkingPipeline:
    """Complete RAG chunking pipeline"""

    def __init__(self):
        self.chunker = HybridChunker(max_tokens=500)
        self.client = OpenAI()
        self.chroma_client = chromadb.Client()
        self.collection = self.chroma_client.create_collection("documents")

    def process_document(self, text: str, metadata: Dict):
        """Chunk, embed, and index document"""

        # 1. Chunk
        chunks = self.chunker.chunk(text)

        # 2. Generate embeddings
        embeddings = self._generate_embeddings([c['text'] for c in chunks])

        # 3. Store in vector database
        self.collection.add(
            embeddings=embeddings,
            documents=[c['text'] for c in chunks],
            metadatas=[{**metadata, **c['metadata']} for c in chunks],
            ids=[f"{metadata['doc_id']}_chunk_{i}" for i in range(len(chunks))]
        )

        return len(chunks)

    def _generate_embeddings(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings using OpenAI"""
        response = self.client.embeddings.create(
            model="text-embedding-3-small",
            input=texts
        )
        return [item.embedding for item in response.data]

    def query(self, question: str, n_results: int = 3) -> List[str]:
        """Query vector database"""
        query_embedding = self._generate_embeddings([question])[0]

        results = self.collection.query(
            query_embeddings=[query_embedding],
            n_results=n_results
        )

        return results['documents'][0]
```

---

# CHUNKING QUALITY METRICS

## How to Evaluate Chunks

```python
class ChunkQualityEvaluator:
    """Evaluate chunking quality"""

    def evaluate(self, chunks: List[str]) -> Dict:
        metrics = {
            'total_chunks': len(chunks),
            'avg_chunk_size': np.mean([len(c) for c in chunks]),
            'chunk_size_std': np.std([len(c) for c in chunks]),
            'min_chunk_size': min(len(c) for c in chunks),
            'max_chunk_size': max(len(c) for c in chunks),
            'boundary_quality': self._eval_boundaries(chunks),
            'context_preservation': self._eval_context(chunks),
            'semantic_coherence': self._eval_coherence(chunks)
        }
        return metrics

    def _eval_boundaries(self, chunks: List[str]) -> float:
        """Check if chunks end at natural boundaries"""
        good_endings = ['.', '!', '?', '\n']
        clean_boundaries = sum(
            1 for c in chunks
            if c.rstrip()[-1] in good_endings
        )
        return clean_boundaries / len(chunks)

    def _eval_context(self, chunks: List[str]) -> float:
        """Check context preservation via overlap similarity"""
        overlaps = []
        for i in range(len(chunks) - 1):
            overlap = self._calculate_overlap(chunks[i], chunks[i+1])
            overlaps.append(overlap)
        return np.mean(overlaps) if overlaps else 0.0
```

---

# BEST PRACTICES

## 1. Chunk Size Selection

```
Small chunks (100-200 tokens):
  ✓ High precision retrieval
  ✓ Fast embedding generation
  ✗ May lose context
  ✗ More chunks to manage

Medium chunks (300-600 tokens):
  ✓ Good balance
  ✓ Preserves context
  ✓ Efficient retrieval
  ✓ Recommended for most use cases

Large chunks (800-1500 tokens):
  ✓ Maximum context
  ✗ Slower retrieval
  ✗ May include irrelevant info
  ✗ More expensive embeddings
```

## 2. Overlap Configuration

```
Overlap = 10-20% of chunk size

Why overlap?
- Prevents information loss at boundaries
- Improves retrieval recall
- Maintains context across chunks

Too little (<5%): Risk losing context
Too much (>30%): Wasted tokens, higher costs
```

## 3. Content-Specific Strategies

```python
# Code documents
chunker = TokenChunker(chunk_tokens=1024, overlap_tokens=100)

# Technical documentation
chunker = HybridChunker(max_tokens=600, overlap_percent=0.15)

# Stories/narrative
chunker = SentenceChunker(target_words=300, overlap_sentences=2)

# Mixed content (blogs)
chunker = HybridChunker(max_tokens=500, overlap_percent=0.20)
```

---

# FILE REFERENCES

- `templates/semantic_chunker.py` - Semantic boundary detection
- `templates/sentence_chunker.py` - Sentence-based chunking
- `templates/hybrid_chunker.py` - Production-ready hybrid chunker
- `templates/rag_pipeline.py` - Complete RAG integration
- `checklists/chunk-quality.md` - Quality evaluation checklist
- `examples/rag-integration.py` - Full RAG system example
- `references/chunk-size-guide.md` - Choosing optimal chunk sizes
- `references/embedding-models.md` - Embedding model comparison
