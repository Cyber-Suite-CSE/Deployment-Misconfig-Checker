from typing import Set, Dict, Any
from urllib.parse import urlparse
from .logger import Logger

def extract_urls_from_target(target_data: Dict[str, Any], logger: Logger) -> Set[str]:
    urls = set()
    
    logger.debug("Extracting URLs from target data...")
    
    if "web_technologies" in target_data:
        web_tech_urls = list(target_data["web_technologies"].keys())
        logger.debug(f"Found {len(web_tech_urls)} URLs in web_technologies")
        for url in web_tech_urls:
            urls.add(url)
            logger.debug(f"Added web_tech URL: {url}")
    
    if "directories" in target_data:
        dir_count = 0
        for directory in target_data["directories"]:
            if "url" in directory:
                urls.add(directory["url"])
                dir_count += 1
                logger.debug(f"Added directory URL: {directory['url']}")
        logger.debug(f"Found {dir_count} URLs in directories")
    
    if "api_endpoints" in target_data:
        api_count = 0
        for endpoint in target_data["api_endpoints"]:
            if "url" in endpoint:
                urls.add(endpoint["url"])
                api_count += 1
                logger.debug(f"Added API endpoint URL: {endpoint['url']}")
        logger.debug(f"Found {api_count} URLs in api_endpoints")
    
    logger.debug(f"Total unique URLs extracted: {len(urls)}")
    return urls

def extract_domains_from_target(target_data: Dict[str, Any], logger: Logger) -> Set[str]:
    domains = set()
    
    logger.debug("Extracting target domains for service-based scanning...")
    
    if "web_technologies" in target_data:
        web_tech_urls = list(target_data["web_technologies"].keys())
        logger.debug(f"Found {len(web_tech_urls)} URLs in web_technologies")
        for url in web_tech_urls:
            domain = parse_domain_from_url(url, logger)
            if domain:
                domains.add(domain)
                logger.debug(f"Extracted domain: {domain}")
    
    if "directories" in target_data:
        dir_count = 0
        for directory in target_data["directories"]:
            if "url" in directory:
                domain = parse_domain_from_url(directory["url"], logger)
                if domain:
                    domains.add(domain)
                    dir_count += 1
                    logger.debug(f"Extracted domain from directory: {domain}")
        logger.debug(f"Found {dir_count} domains in directories")
    
    if "api_endpoints" in target_data:
        api_count = 0
        for endpoint in target_data["api_endpoints"]:
            if "url" in endpoint:
                domain = parse_domain_from_url(endpoint["url"], logger)
                if domain:
                    domains.add(domain)
                    api_count += 1
                    logger.debug(f"Extracted domain from API endpoint: {domain}")
        logger.debug(f"Found {api_count} domains in api_endpoints")
    
    logger.debug(f"Total unique target domains extracted: {len(domains)}")
    return domains

def parse_domain_from_url(url: str, logger: Logger) -> str:
    try:
        parsed = urlparse(url)
        domain = normalize_domain(parsed.netloc)
        return domain
    except Exception as e:
        logger.debug(f"Error parsing URL {url}: {e}")
        return ""

def normalize_domain(domain: str) -> str:
    return domain.replace('www.', '')
