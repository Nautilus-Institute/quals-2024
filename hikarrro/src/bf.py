import hashlib
import hashlib
import random
import string

def generate_random_string(length=10):
    """Generate a random string of fixed length."""
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for _ in range(length))

def sha256_to_integer(input_string):
    """Compute SHA-256 hash of the input string and convert it to an integer."""
    # Encode the string into bytes
    encoded_string = input_string.encode()

    # Compute the SHA-256 hash
    hash_object = hashlib.sha256(encoded_string)

    # Get the hexadecimal representation of the hash
    hex_hash = hash_object.hexdigest()

    # Convert the hexadecimal hash to an integer
    return int(hex_hash, 16)

import hashlib
import random
import string

def generate_random_string(length=10):
    """Generate a random string of fixed length."""
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for _ in range(length))

def sha256_to_integer(input_string):
    """Compute SHA-256 hash of the input string and convert it to an integer."""
    # Encode the string into bytes
    encoded_string = input_string.encode()

    # Compute the SHA-256 hash
    hash_object = hashlib.sha256(encoded_string)

    # Get the hexadecimal representation of the hash
    hex_hash = hash_object.hexdigest()

    # Convert the hexadecimal hash to an integer
    return int(hex_hash, 16)

def find_string_matching_hash(target_hash, max_attempts=1000000000):
    """Attempt to find a string whose SHA-256 hash, as integer, matches the target hash."""
    for attempt in range(max_attempts):
        # Generate a random string
        random_string = generate_random_string()

        # Get the integer hash of the string
        hash_as_integer = sha256_to_integer(random_string)

        # Check if the hash matches the target
        if hash_as_integer%25000001 == target_hash:
            return random_string, hash_as_integer

    return None, None

# Set the target hash value
target_hash = 9212535 #3017134

# Find a matching string
matching_string, final_hash = find_string_matching_hash(target_hash)

if matching_string:
    print(f"Found a string: {matching_string} with hash as integer: {final_hash}")
else:
    print("No matching string found after the specified number of attempts.")



