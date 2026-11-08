#!/bin/bash

BASE_URL="http://10.110.3.72:8014/api/users"
id=1
not_found_count=0
MAX_MISSES=3

echo "Starting user enumeration on port 8014..."

while [ "$not_found_count" -lt "$MAX_MISSES" ]; do
    # Fetch the response body and the HTTP status code separately
    response=$(curl -s -w "\n%{http_code}" "$BASE_URL/$id")
    body=$(echo "$response" | head -n -1)
    http_code=$(echo "$response" | tail -n 1)

    if [ "$http_code" -eq 200 ]; then
        echo "[+] ID $id: $body"
        # Reset the consecutive miss counter on a successful find
        not_found_count=0
    else
        echo "[-] ID $id not found (HTTP $http_code)"
        not_found_count=$((not_found_count + 1))
    fi

    id=$((id + 1))
done

echo "Finished! Stopped after $MAX_MISSES consecutive missing IDs."
