#!/usr/bin/env bash
set -euo pipefail

# Safe, non-secret variables can be written automatically.
railway variables set \
  REQUIRE_EMAIL_VERIFICATION=true \
  EMAIL_PROVIDER=gmail \
  SMTP_HOST=smtp.gmail.com \
  SMTP_PORT=465 \
  SMTP_SECURE=true

# Secrets are deliberately read from the caller's environment so they never
# have to be committed to GitHub.
: "${SMTP_USER:?Set SMTP_USER before running this script}"
: "${SMTP_PASSWORD:?Set SMTP_PASSWORD before running this script}"
: "${BETTER_AUTH_SECRET:?Set BETTER_AUTH_SECRET before running this script}"

railway variables set \
  SMTP_USER="$SMTP_USER" \
  SMTP_PASSWORD="$SMTP_PASSWORD" \
  BETTER_AUTH_SECRET="$BETTER_AUTH_SECRET" \
  EMAIL_FROM="Business Quotes <$SMTP_USER>" \
  RESET_FROM_EMAIL="$SMTP_USER"

if [[ -n "${BETTER_AUTH_URL:-}" ]]; then
  railway variables set BETTER_AUTH_URL="$BETTER_AUTH_URL"
fi
if [[ -n "${CLIENT_URL:-}" ]]; then
  railway variables set CLIENT_URL="$CLIENT_URL"
fi

echo "Railway email/auth variables configured."
