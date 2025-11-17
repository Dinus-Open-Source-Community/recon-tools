from lib.random_ag import rangent
from ..exlib.better_httprobe import safe_httprobe
import os, requests, builtwith

def more_info(target, user_agent=None, proxy=None):
    try:
        report_folder = f"report_{target.replace('/', '_')}"
        subdomain_file = os.path.join(report_folder, "subdomain.txt")
        subdomains_to_scan = []
        
        if os.path.exists(subdomain_file):
            with open(subdomain_file, 'r', encoding='utf-8') as f:
                subdomains_to_scan = [line.strip() for line in f if line.strip()]
        else:
            subdomains_to_scan = [target]
        
        headers = {"User-Agent": user_agent if user_agent else rangent()}
        proxies = {"http": proxy, "https": proxy} if proxy else None
        
        results = []
        output_file = os.path.join(report_folder, "subdomain_with_tech.txt")
        
        with open(output_file, 'w', encoding='utf-8') as tech_file:
            for subdomain in subdomains_to_scan:
                try:
                    url = safe_httprobe(subdomain)
                    technologies = []
                    status = "success"
                    status_code = None
                    error = None
                    
                    try:
                        response = requests.get(url, headers=headers, timeout=10, proxies=proxies, verify=False)
                        status_code = response.status_code
                        
                        if response.status_code == 200:
                            try:
                                tech_data = builtwith.builtwith(url)
                                if tech_data:
                                    for tech_type, tech_list in tech_data.items():
                                        technologies.extend(tech_list)
                                if 'X-Powered-By' in response.headers:
                                    technologies.append(response.headers['X-Powered-By'])
                                if 'Server' in response.headers:
                                    technologies.append(f"Server: {response.headers['Server']}")
                                if 'XSRF-TOKEN' in response.cookies or 'laravel_session' in response.cookies:
                                    technologies.append(f"Framework: Laravel")
                                    
                            except Exception as tech_error:
                                technologies = ["Technology detection failed"]
                        else:
                            status = "error"
                            error = f"Timeout / Host Offline"
                            
                    except requests.Timeout:
                        status = "timeout"
                        error = "Request timeout"
                    except requests.RequestException as e:
                        status = "request_error"
                        error = "Timeout / Host Offline"
                        
                    tech_str = " | ".join(technologies) if technologies else "No technology detected"
                    tech_file.write(f"{url} | {tech_str}\n")
                    
                    results.append({
                        "url": url,
                        "status": status,
                        "status_code": status_code,
                        "error": error,
                        "technologies": technologies
                    })
                    
                except Exception as e:
                    results.append({
                        "url": subdomain,
                        "status": "processing_error",
                        "error": str(e)
                    })
        
        return {"total": len(results), "results": results}
        
    except Exception as e:
        return {
            "error": f"Technology detection failed: {str(e)}",
            "total": 0, 
            "results": []
        }
