# Home

This website provides technical documentation for the `eligibility-api` package from the [California Integrated Travel Project (Cal-ITP)](https://www.calitp.org).

Documentation for the `main` (default) branch is available [online](https://docs.calitp.org/eligibility-api).

## Overview

`eligibility-api` is a Python package that encapsulates the data exchange needed to verify one or more eligibility criteria for transit benefits.

The API is designed for privacy and security of user information:

- The API communicates with signed and encrypted JSON Web Tokens containing only the most necessary of user data for the purpose of eligibility verification
