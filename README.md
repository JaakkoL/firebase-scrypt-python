# firebase-scrypt-python

Python implementation of Firebase's scrypt password hashing algorithm. Based on [https://github.com/firebase/scrypt](https://github.com/firebase/scrypt).

## Installation

Creates virtual environment and installs requirements.

```bash
source ./init-project.sh
```

## Usage

```python

import firebasescrypt

# Sample Password hash parameters from Firebase Console.
salt_separator = "Bw=="
signer_key = "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA=="
rounds= 8
mem_cost=14

# Exported user user accounts salt and password hash.
salt = "42xEC+ixf3L2lw=="
password_hash="lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ=="

# User's plain text password
password = "user1password"

is_valid = firebasescrypt.verify_password(
    password=password,
    known_hash=password_hash,
    salt=salt,
    salt_separator=salt_separator,
    signer_key=signer_key,
    rounds=rounds,
    mem_cost=mem_cost
)

is_valid # True / False

```

## Running tests

```bash
pytest
```
