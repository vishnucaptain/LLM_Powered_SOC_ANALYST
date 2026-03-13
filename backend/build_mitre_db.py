import json
from langchain_core.documents import Document
from langchain_community.vectorstores import Chroma
from langchain_huggingface import HuggingFaceEmbeddings

# Load MITRE dataset
with open("data/enterprise-attack.json") as f:
    data = json.load(f)

documents = []

for obj in data["objects"]:
    
    if obj["type"] == "attack-pattern":
        
        name = obj.get("name", "")
        description = obj.get("description", "")
        
        technique_id = None
        
        if "external_references" in obj:
            for ref in obj["external_references"]:
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")

        if technique_id and description:
            
            text = f"""
Technique ID: {technique_id}
Technique Name: {name}
Description: {description}
"""

            documents.append(
                Document(
                    page_content=text,
                    metadata={"technique_id": technique_id}
                )
            )

print("Loaded techniques:", len(documents))


embedding = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-MiniLM-L6-v2"
)

vector_db = Chroma.from_documents(
    documents,
    embedding,
    persist_directory="vector_db"
)


print("MITRE vector database created.")