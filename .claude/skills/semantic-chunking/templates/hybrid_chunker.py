"""
Production Hybrid Chunker for RAG Systems

Combines semantic boundaries with token limits for optimal RAG performance.
"""

from typing import List, Dict, Optional
from dataclasses import dataclass
import tiktoken
import nltk

# Download required NLTK data
try:
    nltk.data.find('tokenizers/punkt')
except LookupError:
    nltk.download('punkt', quiet=True)


@dataclass
class Chunk:
    """Represents a text chunk with metadata"""
    text: str
    chunk_id: int
    tokens: int
    char_count: int
    start_char: int
    end_char: int
    metadata: Dict


class HybridChunker:
    """
    Production-ready hybrid chunker for RAG applications.

    Features:
    - Respects semantic boundaries (paragraphs, sentences)
    - Enforces token limits for LLM context windows
    - Smart overlap for context preservation
    - Metadata tracking for better retrieval
    """

    def __init__(
        self,
        max_tokens: int = 500,
        overlap_percent: float = 0.15,
        model: str = "gpt-3.5-turbo",
        preserve_paragraphs: bool = True
    ):
        """
        Initialize chunker.

        Args:
            max_tokens: Maximum tokens per chunk
            overlap_percent: Overlap as percentage of max_tokens (0.0-0.5)
            model: Model name for tokenization
            preserve_paragraphs: Try to keep paragraphs intact
        """
        self.max_tokens = max_tokens
        self.overlap_tokens = int(max_tokens * overlap_percent)
        self.model = model
        self.preserve_paragraphs = preserve_paragraphs

        try:
            self.encoding = tiktoken.encoding_for_model(model)
        except KeyError:
            # Fallback for unknown models
            self.encoding = tiktoken.get_encoding("cl100k_base")

    def chunk(self, text: str, metadata: Optional[Dict] = None) -> List[Chunk]:
        """
        Chunk text with semantic boundaries and token limits.

        Args:
            text: Text to chunk
            metadata: Optional metadata to attach to all chunks

        Returns:
            List of Chunk objects
        """

        metadata = metadata or {}
        chunks = []
        current_position = 0

        # First split by paragraphs (double newlines)
        paragraphs = text.split('\n\n')

        current_chunk_parts = []
        current_chunk_tokens = 0

        for para in paragraphs:
            para = para.strip()
            if not para:
                continue

            para_tokens = len(self.encoding.encode(para))

            # If single paragraph exceeds max, split by sentences
            if para_tokens > self.max_tokens:
                # Save current chunk if exists
                if current_chunk_parts:
                    chunk = self._create_chunk(
                        current_chunk_parts,
                        chunks,
                        metadata,
                        current_position
                    )
                    chunks.append(chunk)
                    current_position += len(chunk.text)

                    # Reset with overlap
                    if self.overlap_tokens > 0:
                        overlap_text = self._get_overlap_text(current_chunk_parts)
                        current_chunk_parts = [overlap_text] if overlap_text else []
                        current_chunk_tokens = len(self.encoding.encode(overlap_text)) if overlap_text else 0
                    else:
                        current_chunk_parts = []
                        current_chunk_tokens = 0

                # Split large paragraph by sentences
                sentences = nltk.sent_tokenize(para)

                for sent in sentences:
                    sent_tokens = len(self.encoding.encode(sent))

                    # Check if adding sentence exceeds limit
                    if current_chunk_tokens + sent_tokens > self.max_tokens and current_chunk_parts:
                        # Save current chunk
                        chunk = self._create_chunk(
                            current_chunk_parts,
                            chunks,
                            metadata,
                            current_position
                        )
                        chunks.append(chunk)
                        current_position += len(chunk.text)

                        # Keep overlap
                        if self.overlap_tokens > 0:
                            overlap_text = self._get_overlap_text(current_chunk_parts)
                            current_chunk_parts = [overlap_text] if overlap_text else []
                            current_chunk_tokens = len(self.encoding.encode(overlap_text)) if overlap_text else 0
                        else:
                            current_chunk_parts = []
                            current_chunk_tokens = 0

                    current_chunk_parts.append(sent)
                    current_chunk_tokens += sent_tokens

            # Add paragraph to current chunk
            elif current_chunk_tokens + para_tokens > self.max_tokens and current_chunk_parts:
                # Save current chunk
                chunk = self._create_chunk(
                    current_chunk_parts,
                    chunks,
                    metadata,
                    current_position
                )
                chunks.append(chunk)
                current_position += len(chunk.text)

                # Keep last paragraph for overlap
                if self.overlap_tokens > 0 and current_chunk_parts:
                    overlap_text = self._get_overlap_text(current_chunk_parts)
                    current_chunk_parts = [overlap_text, para] if overlap_text else [para]
                    current_chunk_tokens = len(self.encoding.encode('\n\n'.join(current_chunk_parts)))
                else:
                    current_chunk_parts = [para]
                    current_chunk_tokens = para_tokens

            else:
                # Add to current chunk
                current_chunk_parts.append(para)
                current_chunk_tokens += para_tokens

        # Add final chunk
        if current_chunk_parts:
            chunk = self._create_chunk(
                current_chunk_parts,
                chunks,
                metadata,
                current_position
            )
            chunks.append(chunk)

        return chunks

    def _create_chunk(
        self,
        parts: List[str],
        existing_chunks: List[Chunk],
        metadata: Dict,
        start_position: int
    ) -> Chunk:
        """Create a Chunk object from text parts"""

        # Join parts (preserve paragraph breaks)
        text = '\n\n'.join(parts)
        tokens = len(self.encoding.encode(text))

        chunk_metadata = {
            **metadata,
            'has_overlap': len(existing_chunks) > 0 and self.overlap_tokens > 0,
            'previous_chunk_id': existing_chunks[-1].chunk_id if existing_chunks else None,
            'paragraph_count': len(parts)
        }

        return Chunk(
            text=text,
            chunk_id=len(existing_chunks),
            tokens=tokens,
            char_count=len(text),
            start_char=start_position,
            end_char=start_position + len(text),
            metadata=chunk_metadata
        )

    def _get_overlap_text(self, parts: List[str]) -> str:
        """Get overlap text from end of current chunk"""

        if not parts:
            return ""

        # Take last N tokens worth of text
        combined = '\n\n'.join(parts)
        tokens = self.encoding.encode(combined)

        if len(tokens) <= self.overlap_tokens:
            return combined

        # Take last overlap_tokens
        overlap_token_ids = tokens[-self.overlap_tokens:]
        overlap_text = self.encoding.decode(overlap_token_ids)

        return overlap_text.strip()

    def get_chunk_statistics(self, chunks: List[Chunk]) -> Dict:
        """Get statistics about chunks"""

        if not chunks:
            return {}

        token_counts = [c.tokens for c in chunks]
        char_counts = [c.char_count for c in chunks]

        return {
            'total_chunks': len(chunks),
            'total_tokens': sum(token_counts),
            'total_chars': sum(char_counts),
            'avg_tokens_per_chunk': sum(token_counts) / len(chunks),
            'avg_chars_per_chunk': sum(char_counts) / len(chunks),
            'min_tokens': min(token_counts),
            'max_tokens': max(token_counts),
            'chunks_with_overlap': sum(1 for c in chunks if c.metadata.get('has_overlap', False)),
            'average_paragraphs_per_chunk': sum(c.metadata.get('paragraph_count', 0) for c in chunks) / len(chunks)
        }


# Example usage
if __name__ == "__main__":
    # Sample text
    sample_text = """
    The History of Artificial Intelligence

    Artificial intelligence has a rich history spanning several decades. The term "artificial intelligence" was first coined in 1956 at the Dartmouth Conference. This marked the birth of AI as a field of study.

    Early developments focused on symbolic reasoning and problem-solving. Researchers developed programs that could play chess, prove mathematical theorems, and solve logical puzzles. These early successes led to optimism about the future of AI.

    However, the field experienced several "AI winters" - periods of reduced funding and interest. These occurred in the 1970s and late 1980s when early promises failed to materialize.

    The Modern Era

    The resurgence of AI began in the 1990s with advances in machine learning. Neural networks, particularly deep learning, revolutionized the field. Today, AI powers recommendation systems, autonomous vehicles, and language models.

    Recent breakthroughs include GPT models for natural language processing, AlphaGo for game playing, and DALL-E for image generation. These systems demonstrate capabilities that were science fiction just a decade ago.

    Future Directions

    The future of AI holds both promise and challenges. Researchers are working on artificial general intelligence (AGI) - systems with human-level reasoning across domains. Ethical considerations around AI safety, bias, and accountability are increasingly important.
    """.strip()

    # Initialize chunker
    chunker = HybridChunker(
        max_tokens=200,
        overlap_percent=0.15,
        model="gpt-3.5-turbo"
    )

    # Chunk the text
    chunks = chunker.chunk(
        sample_text,
        metadata={'source': 'AI_history.txt', 'author': 'Example'}
    )

    # Display results
    print(f"Created {len(chunks)} chunks\n")

    for chunk in chunks:
        print(f"Chunk {chunk.chunk_id}:")
        print(f"  Tokens: {chunk.tokens}")
        print(f"  Characters: {chunk.char_count}")
        print(f"  Position: {chunk.start_char}-{chunk.end_char}")
        print(f"  Preview: {chunk.text[:100]}...")
        print()

    # Statistics
    stats = chunker.get_chunk_statistics(chunks)
    print("Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value:.2f}" if isinstance(value, float) else f"  {key}: {value}")
