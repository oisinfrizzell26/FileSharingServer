import re

class UsernameValidator:
    max_username_length = 50
    min_username_length = 6
    reserved_names = {"admin", "test", "null"}
    dangerous_patterns = [
        "../", "..\\",  # Path traversal
        "SELECT", "INSERT", "DROP", "DELETE",  # SQL injection
        "<script", "javascript:", "onload=",  # XSS
        "'", '"', ";", "--"  # SQL injection characters
    ]

    @classmethod
    def validate(cls, username: str):
        """
        Returns (is_valid: bool, error_msg: str)
        """
        username = username.strip()
        if not username:
            return False, "Username cannot be empty"
        if len(username) < cls.min_username_length:
            return False, "Username is too short"
        if len(username) > cls.max_username_length:
            return False, "Username is too long"
        upper_username = username.upper()
        lower_username = username.lower()
        for pattern in cls.dangerous_patterns:
            if pattern.upper() in upper_username or pattern.lower() in lower_username:
                return False, "Username contains invalid characters"
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            return False, "Username can only contain letters, numbers, underscores, and hyphens"
        if username.lower() in cls.reserved_names:
            return False, "Username is reserved"
        return True, ""