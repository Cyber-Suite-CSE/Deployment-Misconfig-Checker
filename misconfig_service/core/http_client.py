import requests
import urllib3
from typing import Dict, Any, List, Optional

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HTTPClient:
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
    
    def make_request(
        self, 
        url: str, 
        method: str = "GET", 
        custom_headers: Optional[List[Dict[str, str]]] = None, 
        body: Optional[str] = None
    ) -> Dict[str, Any]:
        print(f"DEBUG: Making {method} request to {url}")
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            if custom_headers:
                for header_dict in custom_headers:
                    headers.update(header_dict)
            
            print(f"DEBUG: Using headers: {headers}")
            if body:
                print(f"DEBUG: Using body: {body}")
            
            method_upper = method.upper()
            request_kwargs = {
                'headers': headers,
                'timeout': self.timeout,
                'verify': False,
                'allow_redirects': True
            }
            
            if method_upper == "GET":
                response = self.session.get(url, **request_kwargs)
            elif method_upper == "POST":
                response = self.session.post(url, data=body, **request_kwargs)
            elif method_upper == "PUT":
                response = self.session.put(url, data=body, **request_kwargs)
            elif method_upper == "DELETE":
                response = self.session.delete(url, **request_kwargs)
            elif method_upper == "PATCH":
                response = self.session.patch(url, data=body, **request_kwargs)
            else:
                print(f"DEBUG: Unsupported HTTP method: {method}")
                return {
                    "url": url,
                    "error": f"Unsupported HTTP method: {method}",
                    "success": False
                }
            
            print(f"DEBUG: Request successful - Status: {response.status_code}, Content length: {len(response.text)}")
            
            return {
                "url": url,
                "method": method_upper,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "content": response.text,
                "success": True
            }
        except requests.exceptions.RequestException as e:
            print(f"DEBUG: Request failed for {url} - Error: {str(e)}")
            return {
                "url": url,
                "method": method.upper() if method else "GET",
                "error": str(e),
                "success": False
            }
