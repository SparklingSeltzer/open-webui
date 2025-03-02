import logging
from typing import Optional
import platform
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

from open_webui.retrieval.web.main import SearchResult
from open_webui.env import SRC_LOG_LEVELS

import os
import ssl
import certifi
import tempfile
import subprocess

# Configure logging
log = logging.getLogger(__name__)
log.setLevel(SRC_LOG_LEVELS["RAG"])

# Create a more robust SSL context that tries multiple certificate paths
def create_robust_ssl_context():
    context = ssl.create_default_context()
    
    # Try multiple certificate sources
    cert_paths = [
        # Certifi's bundled certificates (cross-platform)
        certifi.where(),
        
        # Environment variable if set
        os.environ.get("SSL_CERT_FILE"),
        
        # macOS specific paths
        "/etc/ssl/cert.pem",
        "/etc/ssl/certs/ca-certificates.crt",
        "/usr/local/etc/openssl/cert.pem",
        "/usr/local/etc/openssl@1.1/cert.pem",
        
        # Homebrew OpenSSL on macOS
        "/opt/homebrew/etc/openssl@3/cert.pem",
        "/opt/homebrew/etc/openssl@1.1/cert.pem",
    ]
    
    # On macOS, add the system keychain certificates
    if platform.system() == 'Darwin':
        try:
            # Extract certificates from the macOS system keychain
            security_process = subprocess.run(
                ["security", "find-certificate", "-a", "-p", "/System/Library/Keychains/SystemRootCertificates.keychain"],
                capture_output=True, 
                text=True
            )
            if security_process.returncode == 0:
                # Create a temporary file with the extracted certificates
                with tempfile.NamedTemporaryFile(delete=False, suffix='.pem') as temp_cert_file:
                    temp_cert_file.write(security_process.stdout.encode())
                    cert_paths.append(temp_cert_file.name)
        except Exception as e:
            log.warning(f"Error accessing macOS keychain: {e}")
    
    # Try to load certificates from each path
    loaded = False
    for path in cert_paths:
        if path:
            try:
                context.load_verify_locations(cafile=path)
                log.info(f"Successfully loaded certificates from: {path}")
                loaded = True
            except Exception as e:
                log.debug(f"Failed to load certificates from {path}: {e}")
    
    if not loaded:
        log.warning("Could not load certificates from any location")
    
    return context

# Create the SSL context using our robust approach
ssl_context = create_robust_ssl_context()

# Custom HTTPAdapter that uses the specified SSL context.
class SSLAdapter(HTTPAdapter):
    def __init__(self, ssl_context=None, **kwargs):
        self.ssl_context = ssl_context
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        if self.ssl_context is not None:
            pool_kwargs["ssl_context"] = self.ssl_context
        return super().init_poolmanager(connections, maxsize, block, **pool_kwargs)

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        if self.ssl_context is not None:
            proxy_kwargs["ssl_context"] = self.ssl_context
        return super().proxy_manager_for(proxy, **proxy_kwargs)

def search_tavily(
    api_key: str,
    query: str,
    count: int,
    filter_list: Optional[list[str]] = None,
    time_range: Optional[str] = "day",
    include_raw_content: Optional[bool] = False,
    include_domains: Optional[list[str]] = ["reuters.com","apnews.com","npr.org","aljazeera.com","bbc.com"],
) -> list[SearchResult]:
    """Search using Tavily's Search API and return the results as a list of SearchResult objects.

    Args:
        api_key (str): A Tavily Search API key
        query (str): The query to search for
        count (int): Number of results to return
        filter_list (Optional[list[str]], optional): Filters to apply. Defaults to None.
        time_range (Optional[str], optional): Time range for results ("day", "week", "month"). Defaults to "day".
        include_raw_content (Optional[bool], optional): Whether to include raw content. Defaults to False.
        include_domains (Optional[list[str]], optional): List of domains to include in search. Defaults to ["reuters.com", "apnews.com", "npr.org", "aljazeera.com", "bbc.com"].

    Returns:
        list[SearchResult]: A list of search results
    """
    url = "https://api.tavily.com/search"
    data = {
        "query": query,
        "api_key": api_key,
        "time_range": time_range,
        "include_raw_content": include_raw_content
    }
    
    # Add include_domains if specified
    if include_domains:
        data["include_domains"] = include_domains

    # Create a session and mount the SSL adapter for https.
    session = requests.Session()
    session.mount("https://", SSLAdapter(ssl_context))

    # Use the robust SSL context for verification
    response = session.post(url, json=data)
    response.raise_for_status()

    json_response = response.json()
    raw_search_results = json_response.get("results", [])

    return [
        SearchResult(
            link=result["url"],
            title=result.get("title", ""),
            snippet=result.get("content"),
        )
        for result in raw_search_results[:count]
    ]
