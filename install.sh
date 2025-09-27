#!/bin/bash

# Linux Diagnostic Agent Installation Script
# This script installs the nanny-agent on a Linux system

set -e

echo "🔧 Linux Diagnostic Agent Installation Script"
echo "=============================================="

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed. Please install Go first:"
    echo ""
    echo "For Ubuntu/Debian:"
    echo "  sudo apt update && sudo apt install golang-go"
    echo ""
    echo "For RHEL/CentOS/Fedora:"
    echo "  sudo dnf install golang"
    echo "  # or"
    echo "  sudo yum install golang"
    echo ""
    exit 1
fi

echo "✅ Go is installed: $(go version)"

# Build the application
echo "🔨 Building the application..."
go mod tidy
make build

# Check if build was successful
if [ ! -f "./nanny-agent" ]; then
    echo "❌ Build failed! nanny-agent binary not found."
    exit 1
fi

echo "✅ Build successful!"

# Ask for installation preference
echo ""
echo "Installation options:"
echo "1. Install system-wide (/usr/local/bin) - requires sudo"
echo "2. Keep in current directory"
echo ""
read -p "Choose option (1 or 2): " choice

case $choice in
    1)
        echo "📦 Installing system-wide..."
        sudo cp nanny-agent /usr/local/bin/
        sudo chmod +x /usr/local/bin/nanny-agent
        echo "✅ Agent installed to /usr/local/bin/nanny-agent"
        echo ""
        echo "You can now run the agent from anywhere with:"
        echo "  nanny-agent"
        ;;
    2)
        echo "✅ Agent ready in current directory"
        echo ""
        echo "Run the agent with:"
        echo "  ./nanny-agent"
        ;;
    *)
        echo "❌ Invalid choice. Agent is available in current directory."
        echo "Run with: ./nanny-agent"
        ;;
esac

# Configuration
echo ""
echo "📝 Configuration:"
echo "Set these environment variables to configure the agent:"
echo ""
echo "export NANNYAPI_ENDPOINT=\"http://your-nannyapi-host:3000/openai/v1\""
echo "export NANNYAPI_MODEL=\"your-model-identifier\""
echo ""
echo "Or create a .env file in the working directory."
echo ""
echo "🎉 Installation complete!"
echo ""
echo "Example usage:"
echo "  ./nanny-agent"
echo "  > On /var filesystem I cannot create any file but df -h shows 30% free space available."
