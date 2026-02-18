"""
Complete RAG (Retrieval Augmented Generation) System Example

Demonstrates integration of:
- Semantic chunking
- Multi-provider pattern (for embeddings)
- Vector database (ChromaDB)
- LLM integration (OpenAI)
"""

import os
from pathlib import Path
from typing import List, Dict, Optional
import chromadb
from openai import OpenAI


# Import our custom chunker
import sys
sys.path.append(str(Path(__file__).parent.parent / 'templates'))
from hybrid_chunker import HybridChunker, Chunk


class RAGSystem:
    """
    Production RAG system with semantic chunking.

    Features:
    - Smart text chunking with semantic boundaries
    - Embedding generation with caching
    - Vector similarity search
    - Context-aware response generation
    """

    def __init__(
        self,
        collection_name: str = "documents",
        chunk_size: int = 500,
        chunk_overlap: float = 0.15,
        embedding_model: str = "text-embedding-3-small"
    ):
        """
        Initialize RAG system.

        Args:
            collection_name: Name for vector database collection
            chunk_size: Maximum tokens per chunk
            chunk_overlap: Overlap percentage (0.0-0.5)
            embedding_model: OpenAI embedding model
        """

        # Initialize chunker
        self.chunker = HybridChunker(
            max_tokens=chunk_size,
            overlap_percent=chunk_overlap,
            model="gpt-3.5-turbo"  # For tokenization
        )

        # Initialize OpenAI client
        self.openai_client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
        self.embedding_model = embedding_model

        # Initialize vector database
        self.chroma_client = chromadb.Client()
        self.collection = self.chroma_client.get_or_create_collection(
            name=collection_name,
            metadata={"description": "RAG document collection"}
        )

        print(f"RAG System initialized with collection: {collection_name}")

    def ingest_document(
        self,
        text: str,
        metadata: Dict,
        document_id: str
    ) -> int:
        """
        Ingest document into RAG system.

        Steps:
        1. Chunk the document
        2. Generate embeddings for each chunk
        3. Store in vector database

        Args:
            text: Document text
            metadata: Document metadata
            document_id: Unique document identifier

        Returns:
            Number of chunks created
        """

        print(f"\nIngesting document: {document_id}")

        # 1. Chunk the document
        chunks = self.chunker.chunk(text, metadata={
            **metadata,
            'document_id': document_id
        })

        print(f"Created {len(chunks)} chunks")

        # 2. Extract text from chunks
        chunk_texts = [chunk.text for chunk in chunks]

        # 3. Generate embeddings (batch for efficiency)
        embeddings = self._generate_embeddings(chunk_texts)

        # 4. Prepare data for storage
        chunk_ids = [f"{document_id}_chunk_{i}" for i in range(len(chunks))]
        chunk_metadatas = [
            {
                **chunk.metadata,
                'chunk_id': chunk.chunk_id,
                'tokens': chunk.tokens,
                'char_count': chunk.char_count,
                'start_char': chunk.start_char,
                'end_char': chunk.end_char
            }
            for chunk in chunks
        ]

        # 5. Store in vector database
        self.collection.add(
            ids=chunk_ids,
            embeddings=embeddings,
            documents=chunk_texts,
            metadatas=chunk_metadatas
        )

        print(f"Stored {len(chunks)} chunks in vector database")

        # Show statistics
        stats = self.chunker.get_chunk_statistics(chunks)
        print(f"\nChunk Statistics:")
        print(f"  Average tokens: {stats['avg_tokens_per_chunk']:.0f}")
        print(f"  Token range: {stats['min_tokens']}-{stats['max_tokens']}")

        return len(chunks)

    def query(
        self,
        question: str,
        n_results: int = 3,
        generate_answer: bool = True
    ) -> Dict:
        """
        Query the RAG system.

        Args:
            question: User question
            n_results: Number of relevant chunks to retrieve
            generate_answer: Generate LLM answer from context

        Returns:
            Dict with retrieved chunks and generated answer
        """

        print(f"\nQuery: {question}")

        # 1. Generate embedding for question
        question_embedding = self._generate_embeddings([question])[0]

        # 2. Retrieve relevant chunks
        results = self.collection.query(
            query_embeddings=[question_embedding],
            n_results=n_results
        )

        # Extract results
        chunks = results['documents'][0] if results['documents'] else []
        metadatas = results['metadatas'][0] if results['metadatas'] else []
        distances = results['distances'][0] if results['distances'] else []

        print(f"Retrieved {len(chunks)} relevant chunks")

        # 3. Generate answer (if requested)
        answer = None
        if generate_answer and chunks:
            answer = self._generate_answer(question, chunks)

        return {
            'question': question,
            'answer': answer,
            'sources': [
                {
                    'text': chunk,
                    'metadata': metadata,
                    'relevance_score': 1 - distance  # Convert distance to similarity
                }
                for chunk, metadata, distance in zip(chunks, metadatas, distances)
            ],
            'num_sources': len(chunks)
        }

    def _generate_embeddings(self, texts: List[str]) -> List[List[float]]:
        """
        Generate embeddings using OpenAI.

        Batches requests for efficiency.
        """

        # OpenAI supports up to 2048 texts per request
        batch_size = 2048
        all_embeddings = []

        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]

            response = self.openai_client.embeddings.create(
                model=self.embedding_model,
                input=batch
            )

            batch_embeddings = [item.embedding for item in response.data]
            all_embeddings.extend(batch_embeddings)

        return all_embeddings

    def _generate_answer(self, question: str, context_chunks: List[str]) -> str:
        """
        Generate answer using LLM with retrieved context.
        """

        # Combine context chunks
        context = "\n\n".join(context_chunks)

        # Create prompt
        prompt = f"""Answer the question based on the context below. If the answer is not in the context, say "I don't have enough information to answer that."

Context:
{context}

Question: {question}

Answer:"""

        # Generate response
        response = self.openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful assistant that answers questions based on provided context."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=500
        )

        return response.choices[0].message.content

    def get_collection_stats(self) -> Dict:
        """Get statistics about the document collection"""

        count = self.collection.count()

        return {
            'total_chunks': count,
            'collection_name': self.collection.name,
            'embedding_model': self.embedding_model
        }


# Example usage
if __name__ == "__main__":
    # Initialize RAG system
    rag = RAGSystem(
        collection_name="ai_knowledge_base",
        chunk_size=400,
        chunk_overlap=0.2
    )

    # Sample documents
    documents = [
        {
            'id': 'doc1',
            'text': """
            The History of Artificial Intelligence

            Artificial intelligence has a rich history spanning several decades. The term "artificial intelligence" was first coined in 1956 at the Dartmouth Conference by John McCarthy, Marvin Minsky, and others. This conference marked the birth of AI as a field of study.

            Early developments focused on symbolic reasoning and problem-solving. Researchers developed programs that could play chess, prove mathematical theorems, and solve logical puzzles. These early successes led to great optimism about the future of AI, with predictions that machines would match human intelligence within a generation.

            However, the field experienced several "AI winters" - periods of reduced funding and interest. These occurred in the 1970s and late 1980s when early promises failed to materialize and the limitations of symbolic AI became apparent.

            The Modern Era

            The resurgence of AI began in the 1990s with advances in machine learning. Neural networks, particularly deep learning, revolutionized the field. The availability of large datasets and powerful GPUs enabled training of complex models that could learn from data rather than relying on hand-coded rules.

            Today, AI powers recommendation systems, autonomous vehicles, language models, and countless other applications. Recent breakthroughs include transformer models like GPT for natural language processing, AlphaGo for game playing, and DALL-E for image generation.
            """,
            'metadata': {
                'title': 'History of AI',
                'author': 'AI Researcher',
                'year': 2024,
                'category': 'History'
            }
        },
        {
            'id': 'doc2',
            'text': """
            Machine Learning Fundamentals

            Machine learning is a subset of artificial intelligence that focuses on building systems that learn from data. Unlike traditional programming where explicit rules are coded, machine learning systems discover patterns in data and use them to make predictions.

            There are three main types of machine learning:

            1. Supervised Learning: The algorithm learns from labeled training data. Examples include image classification, spam detection, and price prediction.

            2. Unsupervised Learning: The algorithm finds patterns in unlabeled data. Common techniques include clustering, dimensionality reduction, and anomaly detection.

            3. Reinforcement Learning: The algorithm learns through trial and error, receiving rewards or penalties. This approach has been successful in game playing, robotics, and autonomous systems.

            Deep Learning

            Deep learning is a specialized form of machine learning using neural networks with multiple layers. These deep networks can learn hierarchical representations of data, extracting features at different levels of abstraction.

            Applications include computer vision (object detection, facial recognition), natural language processing (translation, sentiment analysis), and speech recognition.
            """,
            'metadata': {
                'title': 'Machine Learning Basics',
                'author': 'ML Expert',
                'year': 2024,
                'category': 'Fundamentals'
            }
        }
    ]

    # Ingest documents
    for doc in documents:
        rag.ingest_document(
            text=doc['text'],
            metadata=doc['metadata'],
            document_id=doc['id']
        )

    # Query examples
    print("\n" + "="*80)
    print("QUERY EXAMPLES")
    print("="*80)

    questions = [
        "When was the term 'artificial intelligence' first coined?",
        "What are the three main types of machine learning?",
        "What caused the AI winters?",
        "How does deep learning differ from traditional machine learning?"
    ]

    for question in questions:
        result = rag.query(question, n_results=2, generate_answer=True)

        print(f"\nQ: {result['question']}")
        print(f"A: {result['answer']}")
        print(f"\nSources ({result['num_sources']}):")
        for i, source in enumerate(result['sources'], 1):
            print(f"  {i}. Relevance: {source['relevance_score']:.2%}")
            print(f"     Document: {source['metadata']['title']}")
            print(f"     Preview: {source['text'][:150]}...")

    # Collection statistics
    print("\n" + "="*80)
    stats = rag.get_collection_stats()
    print("Collection Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
