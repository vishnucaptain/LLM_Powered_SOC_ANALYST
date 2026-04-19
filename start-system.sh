#!/bin/bash
# Quick Start: Frontend + Backend RAG Integration
# This script starts both the backend API and prepares the frontend

set -e

PROJECT_DIR="/Users/akashmacbook/Desktop/LLM_Powered_SOC_ANALYST"
cd "$PROJECT_DIR"

echo "🚀 LLM-Powered SOC Analyst - Full Stack Start"
echo "=============================================="
echo ""

# Check if venv exists
if [ ! -d ".venv" ]; then
    echo "❌ Virtual environment not found. Run: python3 -m venv .venv"
    exit 1
fi

# Activate venv
source .venv/bin/activate

# Check if vector_db exists (MITRE database)
if [ ! -f "vector_db/chroma.sqlite3" ]; then
    echo "⚠️  MITRE vector database not found. Building now..."
    python backend/rag/build_mitre_db.py
    echo "✅ MITRE database built"
fi

echo ""
echo "📊 System Check"
echo "==============="

# Check API
echo -n "Checking API... "
python verify_rag.py 2>/dev/null | grep "RAG System Status" && echo "✓ RAG System Ready" || echo "⚠ May need initialization"

echo ""
echo "🎯 Starting Backend API"
echo "======================"
echo "FastAPI will run on: http://localhost:8000"
echo "API docs: http://localhost:8000/docs"
echo ""
echo "Press Ctrl+C to stop"
echo ""

# Start the API server
uvicorn backend.main:app --reload --port 8000 &
API_PID=$!

# Give API time to start
sleep 2

echo ""
echo "✅ Backend API started (PID: $API_PID)"
echo ""
echo "🎨 Frontend"
echo "==========="
echo "Open browser to view frontend:"
echo "  → file:///Users/akashmacbook/Desktop/LLM_Powered_SOC_ANALYST/frontend/index.html"
echo "  → Or: python3 -m http.server 8080 --directory frontend"
echo ""
echo "📚 Documentation"
echo "================"
echo "Full integration guide: FRONTEND_BACKEND_INTEGRATION.md"
echo "RAG setup: RAG_INTEGRATION_SUMMARY.md"
echo ""
echo "✅ System Ready!"
echo "Process Backend API with:"
echo "  kill $API_PID"
echo ""
echo "Waiting for API to run (Ctrl+C to stop)..."
echo ""

# Wait for API
wait $API_PID
