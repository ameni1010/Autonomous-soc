#!/bin/bash

echo "🎯 Launching attack from client container..."
docker exec -it soc-client /app/attack.sh
