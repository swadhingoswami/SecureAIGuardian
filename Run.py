import os
import requests
import subprocess
from transformers import AutoTokenizer

# ***EXTREMELY IMPORTANT SECURITY WARNING***
# Disabling SSL verification is HIGHLY DISCOURAGED due to severe security risks.
# Only do this in controlled development/testing environments, NEVER in production.
# This makes your application vulnerable to man-in-the-middle attacks.

# Option 1: Disable warnings (less intrusive, but still disables verification)
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
os.environ['PYTHONWARNINGS'] = 'ignore:Unverified HTTPS request'

# Option 2: Custom HTTP Client (more explicit, but functionally the same)
class CustomHttpClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification

    def get(self, url, **kwargs):
        return self.session.get(url, **kwargs)

    def post(self, url, **kwargs):
        return self.session.post(url, **kwargs)

# Load the tokenizer (no changes needed here)
def load_tokenizer():
    tokenizer = AutoTokenizer.from_pretrained("dslim/bert-base-NER") #, use_auth_token=True, http_client=CustomHttpClient()) # if you chose option 2
    return tokenizer

tokenizer = load_tokenizer()

subprocess.run(['streamlit', 'run', 'app.py'])