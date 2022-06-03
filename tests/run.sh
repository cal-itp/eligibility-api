#!/usr/bin/env bash
set -eu

pytest --cov=eligibility_api --cov-branch

# clean out old coverage results
rm -rf coverage
coverage html --directory coverage
