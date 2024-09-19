#!/bin/bash
# Add project root to PYTHONPATH to make sure Python can find the modules
export PYTHONPATH=$(pwd)
python3 server/server.py --port 8080
python3 server/server.py --port 8081
python3 server/server.py --port 8082

