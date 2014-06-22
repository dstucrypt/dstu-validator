DSTU remote validator
=====================

This daemon implements HTTP API for certificate verification and signature checks.

Code written in C, uses OpenSSL (with dstu patch) and libre (http://www.creytiv.com/re.html).

CA
--

Trusted certificates should be available in current directory (`./CA/`).

Usage
-----

Send POST request to localhost:8013/api/0/check to verify signature.

Params:

- `d` - data in plain text
- `s` - signature in base64
- `c` - signer certificate in PEM format
