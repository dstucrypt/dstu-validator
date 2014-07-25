DSTU remote validator
=====================

This daemon implements HTTP API for certificate verification and signature checks.

Code written in C, uses OpenSSL with DSTU support [0] and libre [1]

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

Dependencies
------------

Depends on openssl-dstu and creytib re 0.4.9

Links
-----

- [0] https://github.com/muromec/openssl-dstu (branch `dstu-1_0_1h`)
- [1] http://www.creytiv.com/re.html
