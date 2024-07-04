#!/usr/bin/env sh

# Prompt for user input
read -rp "Enter filename: " filename
read -rp "duration: " duration

# Execute curl command
curl -o "./$filename" "http://localhost:6060/debug/pprof/profile?seconds=$duration"
