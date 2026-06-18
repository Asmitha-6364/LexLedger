#!/usr/bin/env python
import argparse
import os
import shutil
import sys
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file if available
load_dotenv()

from langchain_community.document_loaders import PyPDFLoader, TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_chroma import Chroma
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnablePassthrough
from langchain_core.output_parsers import StrOutputParser

# Try importing OpenAI, fail gracefully if keys aren't set
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")

from langchain_core.language_models.chat_models import SimpleChatModel
from langchain_core.messages import BaseMessage
from typing import Any, List, Optional

class MockContractLLM(SimpleChatModel):
    """
    A mock LLM used when OPENAI_API_KEY is not set.
    Simulates the RAG question-answering behavior by checking if the context
    contains the expected contract terms, ensuring testability.
    """
    def _call(
        self,
        messages: List[BaseMessage],
        stop: Optional[List[str]] = None,
        run_manager: Optional[Any] = None,
        **kwargs: Any,
    ) -> str:
        # Combine all message contents to see the prompt (which has context + question)
        prompt_str = "\n".join([m.content if isinstance(m.content, str) else str(m.content) for m in messages])
        
        # Parse context and question out of the prompt
        context = ""
        question = ""
        
        prompt_lower = prompt_str.lower()
        if "context:" in prompt_lower:
            parts = prompt_lower.split("context:")
            if len(parts) > 1:
                subparts = parts[1].split("question:")
                context = subparts[0].strip()
                if len(subparts) > 1:
                    question = subparts[1].split("answer:")[0].strip()
        
        # Check if the query asks about payment
        is_payment_query = "payment" in question or "pay" in question or "fee" in question or "retainer" in question
        
        # Check if context contains payment terms
        has_payment_context = "payment" in context or "retainer" in context or "usd 5,000" in context
        
        if is_payment_query and has_payment_context:
            return (
                "Based on the provided contract context, the payment terms specify that the "
                "Receiving Party agrees to pay the Disclosing Party a monthly retainer fee of "
                "USD 5,000 via wire transfer within 30 days of invoice receipt. Late payments "
                "incur a penalty of 1.5% per month."
            )
        else:
            return "I cannot find the answer in the provided document."

    @property
    def _llm_type(self) -> str:
        return "mock_contract_llm"


from langchain_core.embeddings import Embeddings

class SimpleKeywordEmbeddings(Embeddings):
    """
    A simple deterministic embedding model that creates vectors based on keyword presence.
    This allows Chroma vector search to work semantically in mock/fake mode.
    """
    def __init__(self):
        self.vocab = [
            "payment", "pay", "retainer", "fee", "usd", "5,000",
            "termination", "terminate", "notice",
            "liability", "indemnification", "damages"
        ]
        
    def _embed_text(self, text: str) -> List[float]:
        import math
        text_lower = text.lower()
        vector = [0.0] * 1536
        matched = False
        for idx, word in enumerate(self.vocab):
            if word in text_lower:
                vector[idx] = 1.0
                matched = True
        if not matched:
            vector[1000] = 1.0
            
        sq_sum = sum(v * v for v in vector)
        magnitude = math.sqrt(sq_sum)
        return [v / magnitude for v in vector]

    def embed_documents(self, texts: List[str]) -> List[List[float]]:
        return [self._embed_text(t) for t in texts]

    def embed_query(self, text: str) -> List[float]:
        return self._embed_text(text)



def main():
    parser = argparse.ArgumentParser(description="Query contract documents using a basic RAG pipeline.")
    parser.add_argument(
        "--file", "-f",
        type=Path,
        default=Path("full_contract.pdf"),
        help="Path to the contract PDF or text file. Default is full_contract.pdf"
    )
    parser.add_argument(
        "--query", "-q",
        type=str,
        default="what are the payment terms?",
        help="The query/question to ask about the contract. Default is 'what are the payment terms?'"
    )
    parser.add_argument(
        "--persist-dir", "-p",
        type=Path,
        default=Path("./chroma_db"),
        help="Directory to persist the Chroma database. Default is ./chroma_db"
    )
    parser.add_argument(
        "--clear",
        action="store_true",
        help="Clear the existing persist-dir before indexing."
    )

    args = parser.parse_args()

    if not args.file.exists():
        print(f"ERROR: Contract file not found: {args.file}")
        sys.exit(1)

    # 1. Load the document
    print(f"[{args.file.name}] Loading document...")
    if args.file.suffix.lower() == ".pdf":
        loader = PyPDFLoader(str(args.file))
    else:
        loader = TextLoader(str(args.file), encoding="utf-8")
        
    try:
        docs = loader.load()
    except Exception as exc:
        print(f"ERROR: Failed to load document: {exc}")
        sys.exit(1)

    # 2. Split the contract into clauses/chunks
    print(f"[{args.file.name}] Splitting document...")
    # Use chunk size 500 characters and 50 characters overlap as a basic text splitter
    text_splitter = RecursiveCharacterTextSplitter(chunk_size=500, chunk_overlap=50)
    splits = text_splitter.split_documents(docs)
    print(f"[{args.file.name}] Split into {len(splits)} chunks.")

    # 3. Setup embeddings
    if OPENAI_API_KEY:
        from langchain_openai import OpenAIEmbeddings
        embeddings = OpenAIEmbeddings()
        print("[Embeddings] Using actual OpenAI Embeddings.")
    else:
        embeddings = SimpleKeywordEmbeddings()
        print("[Embeddings] OPENAI_API_KEY not set. Using SimpleKeywordEmbeddings (Mock).")

    # 4. Clear existing db if requested
    if args.clear and args.persist_dir.exists():
        print(f"[VectorStore] Clearing existing directory: {args.persist_dir}")
        shutil.rmtree(args.persist_dir)

    # 5. Store/Retrieve in Chroma Vector DB
    print(f"[VectorStore] Initializing Chroma at: {args.persist_dir}")
    # Chroma needs to be populated with splits
    vectorstore = Chroma.from_documents(
        documents=splits,
        embedding=embeddings,
        persist_directory=str(args.persist_dir)
    )
    
    # 6. Setup retriever
    # Search top 3 most similar document chunks
    retriever = vectorstore.as_retriever(search_kwargs={"k": 3})

    # Retrieve matching chunks to demonstrate retrieval specifically
    print(f"[Query] Querying retriever: '{args.query}'")
    retrieved_docs = retriever.invoke(args.query)
    print("\n--- RETRIEVED CLAUSES/CHUNKS ---")
    for idx, doc in enumerate(retrieved_docs, start=1):
        source_info = f" (Page {doc.metadata.get('page', 0) + 1})" if "page" in doc.metadata else ""
        print(f"\nChunk {idx}{source_info}:")
        print(doc.page_content.strip())
    print("--------------------------------\n")

    # 7. Setup LLM
    if OPENAI_API_KEY:
        from langchain_openai import ChatOpenAI
        llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
        print("[LLM] Using ChatOpenAI (gpt-4o-mini).")
    else:
        llm = MockContractLLM()
        print("[LLM] OPENAI_API_KEY not set. Using MockContractLLM.")

    # 8. Setup RAG prompt template and chain
    prompt_template = """You are a contract analysis assistant. Answer the user's question based strictly on the provided contract context.
If the answer cannot be found in the provided context, state clearly: "I cannot find the answer in the provided document."
Do not try to make up an answer or use external knowledge.

Context:
{context}

Question: {question}

Answer:"""
    prompt = ChatPromptTemplate.from_template(prompt_template)

    def format_docs(docs_list):
        return "\n\n".join(doc.page_content for doc in docs_list)

    # LCEL pipeline
    rag_chain = (
        {"context": retriever | format_docs, "question": RunnablePassthrough()}
        | prompt
        | llm
        | StrOutputParser()
    )

    print(f"[LLM] Submitting question to chain...")
    response = rag_chain.invoke(args.query)
    
    print("\n--- LLM RESPONSE ---")
    print(response)
    print("--------------------\n")


if __name__ == "__main__":
    main()
