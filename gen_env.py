'''
Python script for creating and initializing a basic .env file.
'''
import os
from django.core.management.utils import get_random_secret_key


def gen_env():
    
    secret_key = get_random_secret_key()

    env_template = f"""
    # Production Key
    SECRET_KEY={secret_key}
    # Change in case of production.
    DEBUG=True
    # Define further configuration variables below
    """

    with open('./SecureFlow_Analyzer/.env', 'w') as env_file:
        env_file.write(env_template.strip())
    
if __name__ == "__main__":
    gen_env()