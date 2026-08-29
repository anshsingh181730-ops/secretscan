# A normal file with no secrets
import os

def calculate_total(items):
    return sum(item.price for item in items)

class UserProfile:
    def __init__(self, name, email):
        self.name = name
        self.email = email

DEFAULT_PORT = 8080
DEBUG_MODE = True
MAX_RETRIES = 3