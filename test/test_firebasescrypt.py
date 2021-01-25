import base64
import pytest

from firebasescrypt import (
    generate_derived_key,
    verify_password
)

# Known values from https://github.com/firebase/scrypt#password-hashing
salt_separator = "Bw=="
signer_key = "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA=="
rounds= 8
mem_cost=14

password = "user1password"
salt = "42xEC+ixf3L2lw=="
password_hash="lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ=="

def test_verifies_password_correctly():
    result = verify_password(password, password_hash, salt, salt_separator, signer_key, rounds, mem_cost)
    assert(result)

def test_fails_with_invalid_password():
    invalid_password="secret"
    result = verify_password(invalid_password, password_hash, salt, salt_separator, signer_key, rounds, mem_cost)
    assert(result == False)


def test_generate_derived_key():
    derived_key = generate_derived_key(password, salt, salt_separator, rounds, mem_cost)
    expected_key = "6H+iLZtOO+a71BIU8vmPjHi2lL0X4Swrc1AQVKIJnOEf6JZIPGikQ8bPn/io3+Hf4q2qS+bIyht2hmh6JvSIMQ=="

    assert(base64.b64encode(derived_key).decode('utf-8') == expected_key)