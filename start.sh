#!/bin/bash

echo "Starting Granite Chat Application..."
echo "Installing dependencies..."

# Try to install dependencies
if npm install; then
    echo "Dependencies installed successfully"
else
    echo "Warning: Failed to install dependencies automatically"
    echo "Please run 'sudo chown -R \$(whoami) ~/.npm' to fix npm permissions"
    echo "Then run 'npm install' manually"
fi

echo "Starting server..."
node server.js