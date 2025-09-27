#!/bin/bash

# NannyAPI Function Discovery Script
# This script helps you find the correct function name for your NannyAPI setup

echo "🔍 NannyAPI Function Discovery"
echo "=============================="
echo ""

ENDPOINT="${NANNYAPI_ENDPOINT:-http://nannyapi.local:3000/openai/v1}"

echo "Testing endpoint: $ENDPOINT/chat/completions"
echo ""

# Test common function name patterns
test_functions=(
    "nannyapi::function_name::diagnose"
    "nannyapi::function_name::diagnose_and_heal"
    "nannyapi::function_name::linux_diagnostic"
    "nannyapi::function_name::system_diagnostic"
    "nannyapi::model_name::gpt-4"
    "nannyapi::model_name::claude"
)

for func in "${test_functions[@]}"; do
    echo "Testing function: $func"
    
    response=$(curl -s -X POST "$ENDPOINT/chat/completions" \
        -H "Content-Type: application/json" \
        -d "{\"model\":\"$func\",\"messages\":[{\"role\":\"user\",\"content\":\"test\"}]}")
    
    if echo "$response" | grep -q "Unknown function"; then
        echo "  ❌ Function not found"
    elif echo "$response" | grep -q "error"; then
        echo "  ⚠️  Error: $(echo "$response" | jq -r '.error' 2>/dev/null || echo "$response")"
    else
        echo "  ✅ Function exists and responding!"
        echo "     Use this in your environment: export NANNYAPI_MODEL=\"$func\""
    fi
    echo ""
done

echo "💡 If none of the above work, check your NannyAPI configuration file"
echo "   for the correct function names and update NANNYAPI_MODEL accordingly."
echo ""
echo "Example NannyAPI config snippet:"
echo "```yaml"
echo "functions:"
echo "  diagnose_and_heal:  # This becomes 'nannyapi::function_name::diagnose_and_heal'"
echo "    # function definition"
echo "```"
