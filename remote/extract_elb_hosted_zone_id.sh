#!/bin/sh

# Accept input parameters
LOAD_BALANCER_NAME=$1
OUTPUT_FILE=$2

export ELB_HOSTED_ZONE_ID=$(aws elbv2 describe-load-balancers --output json | jq -r --arg LBNAME "${LOAD_BALANCER_NAME}" '.LoadBalancers[] | select(.LoadBalancerName == "\($LBNAME)") | .CanonicalHostedZoneId')
echo $ELB_HOSTED_ZONE_ID > "$OUTPUT_FILE"
