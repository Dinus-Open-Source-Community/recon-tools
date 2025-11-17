from ..exlib.better_httprobe import safe_httprobe
from ..lib.random_ag import rangent
import os, requests, re

def cms_detection(target, user_agent=None, proxy=None):
    try:
        # CMS detection patterns
        patterns = {
            "wordpress": re.compile(r'(?:<meta name="generator" content="WordPress|/wp-content/|wp-json)'),
            "joomla": re.compile(r'(?:<meta name="generator" content="Joomla|/media/system/js/|/joomla/)'),
            "drupal": re.compile(r'(?:<meta name="generator" content="Drupal|/sites/all/|/core/)'),
            "moodle": re.compile(r'(?:<meta name="keywords" content="moodle|/theme/styles.php)')
        }
        
        results = {cms: [] for cms in patterns.keys()}
        results["unknown"] = []
        
        report_folder = f"report_{target.replace('/', '_')}"
        subdomain_file = os.path.join(report_folder, "subdomain.txt")
        
        subdomains_to_scan = []
        if os.path.exists(subdomain_file):
            with open(subdomain_file, 'r', encoding='utf-8') as f:
                subdomains_to_scan = [line.strip() for line in f if line.strip()]
        else:
            subdomains_to_scan = [target]
        
        # Configure requests
        headers = {"User-Agent": user_agent if user_agent else rangent()}
        proxies = {"http": proxy, "https": proxy} if proxy else None
        
        # Scan each subdomain
        for subdomain in subdomains_to_scan:
            try:
                url = safe_httprobe(subdomain)
                response = requests.get(url, headers=headers, timeout=10, proxies=proxies, verify=False)
                
                if response.status_code == 200:
                    detected_cms = "unknown"
                    
                    for cms_type, pattern in patterns.items():
                        if pattern.search(response.text):
                            detected_cms = cms_type
                            break
                        
            except requests.RequestException:
                continue
        
        # Save results to files
        for cms_type, urls in results.items():
            if urls and cms_type != "unknown":
                with open(os.path.join(report_folder, f"{cms_type}.txt"), "w") as f:
                    f.write("\n".join(urls))
        
        cms_counts = {cms: len(urls) for cms, urls in results.items()}
        
        return {
            "total_scanned": len(subdomains_to_scan),
            "cms_counts": cms_counts,
            "results": results
        }
        
    except Exception as e:
        return {
            "error": f"CMS detection failed: {str(e)}",
            "total_scanned": 0,
            "cms_counts": {"wordpress": 0, "joomla": 0, "drupal": 0, "moodle": 0, "unknown": 0},
            "results": {"wordpress": [], "joomla": [], "drupal": [], "moodle": [], "unknown": []}
        }
