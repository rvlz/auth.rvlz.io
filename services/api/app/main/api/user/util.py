"""User views helper functions."""


def get_unique_col_error_message(error, updates):
    """
    Create message error message for column violating unique constraint.
    """
    error_message = str(error.orig)
    template = '"%s" already exists. Please choose another %s.'
    username = updates.get("username")
    email = updates.get("email")
    if "username" in error_message:
        return template % (username, "username")
    elif "email" in error_message:
        return template % (email, "email address")
    return ""
