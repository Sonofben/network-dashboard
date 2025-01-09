import hashlib
import yaml

def hash_password(password: str) -> str:
    """Hash a password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

# Example passwords
passwords = {
    "yourusername": "yourpassword",
    "anotheruser": "anotherpassword"
}

# Hash the passwords
hashed_passwords = {user: hash_password(pw) for user, pw in passwords.items()}

# Update the config.yaml file
config = {
    "credentials": {
        "usernames": {
            "yourusername": {
                "name": "Your Name",
                "password": hashed_passwords["yourusername"]
            },
            "anotheruser": {
                "name": "Another User",
                "password": hashed_passwords["anotheruser"]
            }
        }
    },
    "cookie": {
        "name": "yourcookie",
        "key": "yourcookiekey",
        "expiry_days": 30
    },
    "preauthorized": {
        "emails": ["youremail@example.com"]
    }
}

# Write the updated config to a file
with open('config.yaml', 'w') as file:
    yaml.dump(config, file)

print("Passwords hashed and config.yaml updated successfully.")
