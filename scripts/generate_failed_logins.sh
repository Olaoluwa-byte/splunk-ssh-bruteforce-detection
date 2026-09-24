#!/bin/bash
# Simulates SSH password guessing against localhost (MITRE T1110.001)
TARGET="127.0.0.1"
USERS=("fakeuser" "admin" "root" "test" "yuji")
for i in $(seq 1 25); do
  USER=${USERS[$((i % ${#USERS[@]}))]}
  sshpass -p "wrong$i" ssh -o StrictHostKeyChecking=no \
    -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    -o ConnectTimeout=5 "$USER@$TARGET" exit 2>/dev/null
done
echo "Done: 25 failed attempts against $TARGET"
