from lib.utility import create_report_folder, clean, safe_remove
from ..exlib.safe_shell import  safe_shell_exec
import nmap, os, shlex

def subdo_scanning(target):
    try:
        report_dir = target.replace('/', '_')
        create_report_folder(report_dir)
        
        # Initialize nmap scanner
        port_scan = nmap.PortScanner()
        
        subdo_set = set()
        
        subfinder_result = safe_shell_exec(f"subfinder -d {shlex.quote(target)} -silent")
        if subfinder_result['success'] and subfinder_result['stdout']:
            subdo_set.update([line.strip() for line in subfinder_result['stdout'].split('\n') if line.strip()])
        
        assetfinder_result = safe_shell_exec(f"assetfinder {shlex.quote(target)}")
        if assetfinder_result['success'] and assetfinder_result['stdout']:
            subdo_set.update([line.strip() for line in assetfinder_result['stdout'].split('\n') if line.strip()])
        
        if not subdo_set:
            common_subdomains = [
                f"www.{target}", f"mail.{target}", f"ftp.{target}", 
                f"cpanel.{target}", f"webmail.{target}", f"admin.{target}",
                f"blog.{target}", f"api.{target}", f"test.{target}"
            ]
            
            for subdomain in common_subdomains:
                try:
                    socket.gethostbyname(subdomain)
                    subdo_set.add(subdomain)
                except socket.gaierror:
                    continue
        
        cpanel_prefixes = ("cpanel.", "webdisk.", "webmail.", "cpcontacts.", "whm.", 
                          "autoconfig.", "mail.", "cpcalendars.", "autodiscover.")
        
        cpanel_subdo = [sub for sub in subdo_set if sub.startswith(cpanel_prefixes)]
        not_cpanel_subdo = [sub for sub in subdo_set if not sub.startswith(cpanel_prefixes)]
        
        # Save results
        report_folder = f"report_{report_dir}"
        with open(os.path.join(report_folder, "cpanel_subdomain.txt"), "w") as f:
            f.write("\n".join(cpanel_subdo))
        
        with open(os.path.join(report_folder, "subdomain.txt"), "w") as f:
            f.write("\n".join(not_cpanel_subdo))
        
        # Scan subdomains with nmap
        results = []
        for subdomain in subdo_set:
            subdomain_info = {"subdomain": subdomain, "ports": []}
            
            try:
                scan_result = port_scan.scan(hosts=subdomain, arguments="-F --host-timeout 30s")
                
                if "scan" in scan_result:
                    hosts = list(scan_result["scan"].keys())
                    if hosts and hosts[0] in scan_result["scan"]:
                        host_data = scan_result["scan"][hosts[0]]
                        if "tcp" in host_data:
                            open_ports = list(host_data["tcp"].keys())
                            subdomain_info["ports"] = open_ports
                            subdomain_info["status"] = "online"
                        else:
                            subdomain_info["status"] = "no_open_ports"
                    else:
                        subdomain_info["status"] = "host offline"
                else:
                    subdomain_info["status"] = "scan_failed"
                    
            except Exception as e:
                subdomain_info["status"] = "error"
                subdomain_info["error"] = str(e)
            
            results.append(subdomain_info)
        
        return {
            "total": len(subdo_set),
            "cpanel": len(cpanel_subdo),
            "non_cpanel": len(not_cpanel_subdo),
            "results": results
        }
        
    except Exception as e:
        return {"error": f"Subdomain scanning failed: {str(e)}", "total": 0, "results": []}