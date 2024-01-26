import re

from pydantic import BaseModel, constr, field_validator, EmailStr


class RegisterUser(BaseModel):
    email: EmailStr
    password: constr(min_length=8, max_length=50)
    registration_type: str

    @field_validator("email")
    def validate_email(cls, email: str):
        try:
            # ================================================================
            # Basic email format validation
            # ================================================================
            if "@" not in email:
                raise ValueError("Invalid email format")

            # ================================================================
            # We can add more complex validation for the domain if needed
            # For simplicity, we're just checking for the presence of a dot (.)
            # ================================================================
            if "." not in email.split("@")[1]:
                raise ValueError("Invalid email domain")

            return email
        except Exception:
            raise

    @field_validator("password")
    def validate_password(cls, password: str):
        try:
            # ================================================================
            # Check for at least one special character, one digit, and one letter
            # ================================================================
            if not re.search(r"(?=.*[!@#$%^&*(),.?\":{}|<>])(?=.*\d)(?=.*[a-zA-Z])", password):
                raise ValueError("Password must contain at least one special character, one digit, and one letter")

            return password
        except Exception:
            raise

    @field_validator("registration_type")
    def validate_registration_type(cls, registration_type):
        try:
            allowed_types = ["email"]
            if registration_type.lower() not in allowed_types:
                raise ValueError(f"Invalid registration type. Allowed types: {', '.join(allowed_types)}")
            return registration_type.lower()
        except Exception:
            raise
