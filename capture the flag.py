"""
The following program implements a pin-based authentication system.

The system has two users. User 0 is the superuser available for admin
tasks. Login is disabled for user 0. User 1 is a regular user who can
login with pin 3565. Your task is to login as the disabled superuser.

On exploiting the bypass, you will be given a flag to submit.

It is recommended to analyze this code both by reading it and by running
it in a debugger to deeply explore its inner workings.

The assumed knowledge for this assignment is an understanding of the
following in Python:

- Expressions and operators (+, -, *, /, //, %)
- Variables and assignment
- print, input, and exit
- If/elif/else conditionals
- Exceptions and proper exception handling
- Functions

It may also be helpful, though not strictly neccessary, to have a
basic understanding of password verification using cryptographic
hash functions. As a basic overview, we choose not to store user
passwords (or pins) in cleartext for security reasons. Instead,
we store a hash digest that can be computed from the password, but
from which a password cannot easily be recovered. In order to
authenticate a user, we ensure the digest computed from their
entered credentials matches their stored hash digest.
"""

def get_user_hash(user_id):
    """
    Return a pin hash digest for a specified user_id

    :param user_id: The user identifier as a string
    :return: The hash digest for the user as an int
    """
    if user_id == "0":
        # User 0 is superuser
        # Login is disabled
        return None
    if user_id == "1":
        return 14712
    else:
        print("Invalid User ID:", user_id)
        return None

def hash_pin(pin):
    """
    Compute a hash for a user PIN

    :param pin: The entered pin as a string
    :return: The computed hash digest for this pin
    """
    pin = 3 * pin + 1395
    pin = 30289277 // pin
    pin = pin * 49223 % 99991
    return pin

def authenticate(user_id, pin):
    """
    Authenticate a user

    :param user_id: The user identifier as a string
    :param pin: The entered pin as a string
    :return: True if user_id and pin match, False otherwise
    """
    try:
        pin = int(pin)
        if hash_pin(pin) == get_user_hash(user_id):
            print("Authentication successful")
            return True
        else:
            print("Authentication failure")
            return False
    except:
        print("Error: Pin must be a number")
        # Terminate by recreating error so the user can see it
        int(pin)

# Collect user ID and pin
user_id = input("Enter user ID: ")
pin = input("Enter access PIN number: ")

# Terminate program on invalid credentials
if authenticate(user_id, pin) == False:
    exit()

# Print status after successful login
print("You are logged in as user", user_id)

# Check for auth bypass and display flag
try:
    hash_pin(int(pin))
except:
    print("Auth bypass successful")
    print("Your flag is", 7 * (int(pin) + 1023))
    
    #Flag is 