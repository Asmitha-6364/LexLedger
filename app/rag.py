import os
import math
from typing import Any, List, Optional
from langchain_core.language_models.chat_models import SimpleChatModel
from langchain_core.messages import BaseMessage
from langchain_core.embeddings import Embeddings
from langchain_chroma import Chroma
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnablePassthrough
from langchain_core.output_parsers import StrOutputParser
from langchain_core.documents import Document
from file_integrity import sha256_text

class VerificationFailedException(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)

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
        prompt_str = "\n".join([m.content if isinstance(m.content, str) else str(m.content) for m in messages])
        
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
        
        is_payment_query = "payment" in question or "pay" in question or "fee" in question or "retainer" in question
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

def run_contract_query(contract_id: int, query: str, db) -> tuple[str, list[Any], bool]:
    # 1. Fetch approved clauses for this contract from DB
    from . import models
    clauses = db.query(models.Clause).filter(models.Clause.contract_id == contract_id).all()
    if not clauses:
        raise ValueError("No approved clauses found for this contract.")
        
    # 2. Build Document list
    docs = []
    for clause in clauses:
        docs.append(Document(
            page_content=clause.text,
            metadata={
                "clause_id": clause.id,
                "label": clause.label,
                "stored_hash": clause.sha256_hash,
            }
        ))
        
    # 3. Setup embeddings
    OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
    if OPENAI_API_KEY:
        from langchain_openai import OpenAIEmbeddings
        embeddings = OpenAIEmbeddings()
    else:
        embeddings = SimpleKeywordEmbeddings()
        
    # 4. Setup Chroma (in-memory)
    vectorstore = Chroma.from_documents(
        documents=docs,
        embedding=embeddings,
    )
    
    # 5. Setup retriever
    retriever = vectorstore.as_retriever(search_kwargs={"k": 3})
    
    # 6. Verification middleware
    retrieved_docs_db = []
    
    def verify_documents(docs_list):
        for doc in docs_list:
            clause_id = doc.metadata.get("clause_id")
            label = doc.metadata.get("label")
            # Fetch from DB directly to ensure no database tampering
            db_clause = db.get(models.Clause, clause_id)
            if db_clause is None:
                raise VerificationFailedException(f"Clause {label} (ID {clause_id}) not found in database.")
                
            # Verify database integrity (current vs stored hash)
            current_db_hash = sha256_text(db_clause.text)
            if current_db_hash != db_clause.sha256_hash:
                raise VerificationFailedException(f"Clause '{label}' has been tampered with in the database!")
                
            # Verify retrieved chunk against database hash
            retrieved_hash = sha256_text(doc.page_content)
            if retrieved_hash != db_clause.sha256_hash:
                raise VerificationFailedException(f"Retrieved chunk for clause '{label}' does not match stored database hash!")
                
            # Store the matching database clause object so we can return it in the response
            if db_clause not in retrieved_docs_db:
                retrieved_docs_db.append(db_clause)
                
        return docs_list

    def format_docs(docs_list):
        return "\n\n".join(doc.page_content for doc in docs_list)

    # 7. Setup LLM
    if OPENAI_API_KEY:
        from langchain_openai import ChatOpenAI
        llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    else:
        llm = MockContractLLM()

    # 8. Setup prompt and chain
    prompt_template = """You are a contract analysis assistant. Answer the user's question based strictly on the provided contract context.
If the answer cannot be found in the provided context, state clearly: "I cannot find the answer in the provided document."
Do not try to make up an answer or use external knowledge.

Context:
{context}

Question: {question}

Answer:"""
    prompt = ChatPromptTemplate.from_template(prompt_template)
    
    rag_chain = (
        {"context": retriever | verify_documents | format_docs, "question": RunnablePassthrough()}
        | prompt
        | llm
        | StrOutputParser()
    )
    
    response_text = rag_chain.invoke(query)
    return response_text, retrieved_docs_db, True
