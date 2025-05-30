#!/bin/bash

# Check if there are any running "node" processes
if pgrep node > /dev/null; then
    # Kill all "node" processes
    pkill -9 node
    echo "Killed all 'node' processes."
fi

# Start the process to read and output the content of toto.txt
nohup node index.js &
