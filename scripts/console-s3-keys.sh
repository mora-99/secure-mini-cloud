#!/usr/bin/env bash
# Copies the Garage keys from ~/.mc-keys into console/.env without printing them.
set -euo pipefail
ENV_FILE="$HOME/secure-mini-cloud/console/.env"

get() {  # get <keyfile> <label>
  awk -v label="$2" 'index($0, label) {print $NF; exit}' "$HOME/.mc-keys/$1.txt"
}

RW_ID=$(get app-rw "Key ID");      RW_SEC=$(get app-rw "Secret key")
RO_ID=$(get auditor-ro "Key ID");  RO_SEC=$(get auditor-ro "Secret key")

for v in RW_ID RW_SEC RO_ID RO_SEC; do
  [ -n "${!v}" ] || { echo "ERROR: could not read $v from ~/.mc-keys" >&2; exit 1; }
done

sed -i '/^S3_/d' "$ENV_FILE"
{
  echo "S3_RW_KEY_ID=$RW_ID"
  echo "S3_RW_SECRET=$RW_SEC"
  echo "S3_RO_KEY_ID=$RO_ID"
  echo "S3_RO_SECRET=$RO_SEC"
} >> "$ENV_FILE"
chmod 600 "$ENV_FILE"

echo "Saved. Lengths only (secrets not shown):"
awk -F= '{print "  " $1, "length:", length($2)}' "$ENV_FILE"
