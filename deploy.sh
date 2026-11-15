#!/usr/bin/env bash
set -euo pipefail

STACK_NAME="${STACK_NAME:-zerodrop}"
REGION="${AWS_REGION:-us-east-1}"
ALERT_EMAIL="${1:-${ALERT_EMAIL:-}}"

echo "🔨 Building ZeroDrop with AWS SAM (no pipelines, no servers)..."
sam build --template-file template.yaml

if ! command -v openssl >/dev/null 2>&1; then
  echo "Error: openssl is required to generate a private IP hash salt." >&2
  exit 1
fi
IP_HASH_SALT="$(openssl rand -hex 32)"
PARAM_OVERRIDES=("IpHashSalt=$IP_HASH_SALT")
if [[ -n "$ALERT_EMAIL" ]]; then
  PARAM_OVERRIDES+=("AlertEmail=$ALERT_EMAIL")
fi

echo "🚀 Deploying serverless stack '$STACK_NAME' in $REGION..."
sam deploy \
  --stack-name "$STACK_NAME" \
  --region "$REGION" \
  --resolve-s3 \
  --capabilities CAPABILITY_IAM \
  --no-confirm-changeset \
  --no-fail-on-empty-changeset \
  --parameter-overrides "${PARAM_OVERRIDES[@]}"

WEB_BUCKET=$(aws cloudformation describe-stacks \
  --stack-name "$STACK_NAME" \
  --region "$REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='WebBucketName'].OutputValue" \
  --output text)

DIST_ID=$(aws cloudformation describe-stacks \
  --stack-name "$STACK_NAME" \
  --region "$REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='CloudFrontDistributionId'].OutputValue" \
  --output text)

WEBSITE_URL=$(aws cloudformation describe-stacks \
  --stack-name "$STACK_NAME" \
  --region "$REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='WebsiteUrl'].OutputValue" \
  --output text)

echo "📦 Uploading single-file ZeroDrop UI to private S3 bucket s3://$WEB_BUCKET..."
aws s3 cp web/index.html "s3://$WEB_BUCKET/index.html" \
  --region "$REGION" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "max-age=60"

echo "♻️  Refreshing CloudFront cache..."
aws cloudfront create-invalidation \
  --distribution-id "$DIST_ID" \
  --paths "/*" >/dev/null

echo ""
echo "✅ ZeroDrop is LIVE!"
echo "🌐 Website URL : $WEBSITE_URL"
if [[ -n "$ALERT_EMAIL" ]]; then
  echo "📧 IMPORTANT   : Confirm the AWS SNS subscription email sent to $ALERT_EMAIL!"
fi
echo "🧹 Cleanup later: aws s3 rm s3://$WEB_BUCKET --recursive && sam delete --stack-name $STACK_NAME --region $REGION"
