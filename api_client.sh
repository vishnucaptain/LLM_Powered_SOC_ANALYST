#!/bin/bash
# API Client Script for LLM-Powered SOC Analyst
# Usage: ./api_client.sh [command] [args...]

set -e

BASE_URL="${BASE_URL:-http://localhost:8000}"
TOKEN_FILE=".api_token"

# Color codes
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
print_header() {
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}\n"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ️  $1${NC}"
}

# Get authentication token
get_token() {
    print_header "Getting Authentication Token"
    
    USERNAME="${1:-analyst}"
    PASSWORD="${2:-password123}"
    
    print_info "Username: $USERNAME"
    
    RESPONSE=$(curl -s -X POST "$BASE_URL/auth/token" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}")
    
    TOKEN=$(echo "$RESPONSE" | jq -r '.access_token' 2>/dev/null || echo "")
    
    if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
        print_error "Failed to get token"
        echo "$RESPONSE"
        exit 1
    fi
    
    echo "$TOKEN" > "$TOKEN_FILE"
    print_success "Token saved to $TOKEN_FILE"
    echo "Token: ${TOKEN:0:50}..."
}

# Check API health
check_health() {
    print_header "Checking API Health"
    
    RESPONSE=$(curl -s -X GET "$BASE_URL/health")
    echo "$RESPONSE" | jq '.'
}

# Run investigation
investigate() {
    print_header "Running Investigation"
    
    LOGS="${1:-{\"source\": \"test\", \"events\": [{\"action\": \"login\", \"result\": \"success\"}]}}"
    
    if [ ! -f "$TOKEN_FILE" ]; then
        print_error "No token found. Run: ./api_client.sh login"
        exit 1
    fi
    
    TOKEN=$(cat "$TOKEN_FILE")
    
    print_info "Sending logs for analysis..."
    
    # Use jq to safely construct JSON payload
    PAYLOAD=$(jq -n --arg logs "$LOGS" '{logs: $logs}')
    
    RESPONSE=$(curl -s -X POST "$BASE_URL/investigate" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD")
    
    # Check for errors
    if echo "$RESPONSE" | jq -e '.detail' > /dev/null 2>&1; then
        print_error "API returned error:"
        echo "$RESPONSE" | jq '.detail'
        exit 1
    fi
    
    print_success "Investigation complete!"
    echo "$RESPONSE" | jq '.'
}

# Get user info
get_user_info() {
    print_header "Getting User Info"
    
    if [ ! -f "$TOKEN_FILE" ]; then
        print_error "No token found. Run: ./api_client.sh login"
        exit 1
    fi
    
    TOKEN=$(cat "$TOKEN_FILE")
    
    RESPONSE=$(curl -s -X GET "$BASE_URL/auth/me" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json")
    
    echo "$RESPONSE" | jq '.'
}

# List available demo users
list_users() {
    print_header "Available Demo Users"
    cat << EOF
Username: analyst
Password: password123

Username: admin
Password: admin123

Username: soc_team
Password: team123

⚠️  These are demo credentials. Change them in production!
EOF
}

# Show help
show_help() {
    cat << EOF
${BLUE}LLM-Powered SOC Analyst - API Client${NC}

${YELLOW}Usage:${NC}
  ./api_client.sh [command] [args]

${YELLOW}Commands:${NC}
  login [username] [password]   Get authentication token
                                (default: analyst / password123)
  
  health                        Check API health status
  
  investigate [logs]            Run investigation on logs
                                (default: benign login event)
  
  me                            Get current user info
  
  users                         List available demo users
  
  help                          Show this help message

${YELLOW}Environment Variables:${NC}
  BASE_URL                      API base URL (default: http://localhost:8000)

${YELLOW}Examples:${NC}
  # Get admin token
  ./api_client.sh login admin admin123
  
  # Check API is running
  ./api_client.sh health
  
  # Run investigation
  ./api_client.sh investigate
  
  # Get current user info
  ./api_client.sh me
EOF
}

# Main command router
case "${1:-help}" in
    login)
        get_token "$2" "$3"
        ;;
    health)
        check_health
        ;;
    investigate)
        investigate "$2"
        ;;
    me)
        get_user_info
        ;;
    users)
        list_users
        ;;
    help)
        show_help
        ;;
    *)
        print_error "Unknown command: $1"
        echo ""
        show_help
        exit 1
        ;;
esac
