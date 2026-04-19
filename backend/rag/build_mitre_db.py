import json
import os
from langchain_core.documents import Document
from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter

# Change to project root for relative paths
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(project_root)

# Load MITRE dataset
with open("data/enterprise-attack.json") as f:
    data = json.load(f)

documents = []

for obj in data["objects"]:
    
    if obj.get("type") == "attack-pattern":
        
        name = obj.get("name", "")
        description = obj.get("description", "")
        
        # Extract technique ID
        technique_id = None
        if "external_references" in obj:
            for ref in obj["external_references"]:
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")

        # Extract tactic
        tactics = []
        if "kill_chain_phases" in obj:
            for phase in obj["kill_chain_phases"]:
                if phase.get("kill_chain_name") == "mitre-attack":
                    tactics.append(phase.get("phase_name"))

        if technique_id and description:
            
            text = f"""
Technique ID: {technique_id}
Technique Name: {name}
Tactics: {', '.join(tactics)}
Description: {description}
"""

            documents.append(
                Document(
                    page_content=text,
                    metadata={
                        "technique_id": technique_id,
                        "name": name,
                        "tactics": tactics
                    }
                )
            )

print("Loaded techniques:", len(documents))


# 🔥 Split long documents
text_splitter = RecursiveCharacterTextSplitter(
    chunk_size=500,
    chunk_overlap=50
)

split_docs = text_splitter.split_documents(documents)
print(f"Split into {len(split_docs)} chunks")


# Embeddings
embedding = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-MiniLM-L6-v2"
)

# Vector DB
vector_db = Chroma.from_documents(
    split_docs,
    embedding,
    persist_directory="vector_db"
)

print("MITRE vector database created successfully.")