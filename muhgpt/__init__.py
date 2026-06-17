"""MuhGPT: a human-in-the-loop pentest and OSINT CLI assistant."""
import warnings

# macOS system Python links LibreSSL, which makes urllib3 v2 emit a noisy
# NotOpenSSLWarning the moment requests is imported. Filtering it here — at
# package import, which always runs before a submodule pulls in requests — keeps
# startup clean without needing import-order gymnastics in main.py.
warnings.filterwarnings("ignore", message=r"urllib3 v2 only supports OpenSSL")

__version__ = "1.0.0"
