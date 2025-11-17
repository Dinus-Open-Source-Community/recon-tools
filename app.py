from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess
import os
import json
import threading
import re
import time
from datetime import datetime
from lib.color import Color
from lib.utility import create_report_folder, clean
from lib.random_ag import rangent
from lib.distro import distro

app = Flask(__name__)
CORS(app, resources={
    r"/api/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type"]
    }
})

app.config['SCAN_RESULTS_PATH'] = 'scan_results'
os.makedirs(app.config['SCAN_RESULTS_PATH'], exist_ok=True)

active_scans = {}

def waf_scanning(target):
    """Detect WAF on target"""
    create_report_folder(target)
    try:
        
        host = subprocess.check_output(f"echo {target} | httprobe", shell=True, text=True).strip()
        if not host:
            host = target
            
        
        waf_output = subprocess.check_output(f"wafw00f {host}", shell=True, text=True)
        
        result = {
            "detected": False,
            "name": None,
            "output": waf_output
        }
        
        if "is behind" in waf_output:
            
            match = re.search(r'is behind\s(.+?)\s\(', waf_output)
            if match:
                wafname = match.group(1).strip()
                result["detected"] = True
                result["name"] = wafname
                print(f"{Color.bold}{Color.green}\n\t  [+] WAF: DETECTED [ {wafname} ]{Color.reset}")
            else:
                print(f"{Color.bold}{Color.red}\n\t  [-] WAF: DETECTION FAILED {Color.reset}")
        else:
            print(f"{Color.bold}{Color.yellow}\n\t  [-] WAF: NOT DETECTED {Color.reset}")
            
        return result
    except subprocess.CalledProcessError as e:
        print(f"{Color.bold}{Color.red}\n\t  [-] ERROR: {e}{Color.reset}")
        return {"detected": False, "name": None, "error": str(e)}

def subdo_scanning(target):
    """Scan for subdomains"""
    
    try:
        import nmap
    except ImportError as error:
        print("\n\t   [!] Error on import", error)
        dis = distro()
        if dis == 'arch':
            print("\n\t   [!] Installing python-nmap...")
            subprocess.run(["yay", "-S", "python-nmap", "--noconfirm"])
        else:
            subprocess.run(["pip3", "install", "python-nmap"])
        import nmap
    
    
    report_dir = f"{target}"
    create_report_folder(report_dir)
    port_scan = nmap.PortScanner()
    
    
    subprocess.run(["subfinder", "-d", f"{target}", "-o", ".list_subfinder.txt", "-silent"], 
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    
    subprocess.run(["sublist3r", "-d", f"{target}", "-o", ".list_sublist3r.txt"], 
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    
    subprocess.run(["assetfinder", target], 
                  stdout=open('.list_assetfinder.txt', 'w'), stderr=subprocess.DEVNULL)
    
    
    os.system("cat .list*.txt > .list_subdo.txt")
    
    with open(".list_subdo.txt", encoding="utf-8") as subdo_file:
        subdo_list = subdo_file.read().splitlines()
    
    
    subdoo_list = set(subdo_list)
    
    
    cpanel_subdo = [sub for sub in subdoo_list if sub.startswith(("cpanel.", "webdisk.", "webmail.", 
                                                                "cpcontacts.", "whm.", "autoconfig.", 
                                                                "mail.", "cpcalendars.", "autodiscover."))]
    not_cpanel_subdo = [sub for sub in subdoo_list if not sub.startswith(("cpanel.", "webdisk.", "webmail.", 
                                                                         "cpcontacts.", "whm.", "autoconfig.", 
                                                                         "mail.", "cpcalendars.", "autodiscover."))]
    
    with open(os.path.join(f"report_{report_dir}", "cpanel_subdomain.txt"), "w") as f:
        f.write("\n".join(cpanel_subdo))
    
    with open(os.path.join(f"report_{report_dir}", "subdomain.txt"), "w") as f:
        if not_cpanel_subdo:
            f.write("\n".join(not_cpanel_subdo))
        else:
            f.write("")
    
    clean("txt")
    
    print(f"{Color.bold}{Color.green}\n\t  [+] SUBDOMAINS DETECTED: {len(subdoo_list)}{Color.reset}")
    
    results = []
    for su in subdoo_list:
        
        qscan = port_scan.scan(hosts=su, arguments="-F")
        subdomain_info = {"subdomain": su, "ports": []}
        
        
        if "scan" in qscan:
            h = list(qscan["scan"].keys())
            if len(h) > 0:
                if "tcp" in qscan["scan"][h[0]]:
                    open_ports = list(qscan["scan"][h[0]]["tcp"].keys())
                    subdomain_info["ports"] = open_ports
                    subdomain_info["status"] = "online"
                    print(f"{Color.green}\t    -> {Color.reset}{Color.bold}{su} | {Color.green}{str(open_ports)}{Color.reset}")
                else:
                    subdomain_info["status"] = "no_open_ports"
                    print(f"{Color.reset}{Color.green}\t    -> {Color.reset}{Color.bold}{su} | {Color.red} THERE NO OPEN PORTS{Color.reset}")
            else:
                subdomain_info["status"] = "offline"
                print(f"{Color.green}\t    -> {Color.reset}{Color.bold}{su} | {Color.red}HOST OFFLINE{Color.reset}")
        else:
            subdomain_info["status"] = "scan_failed"
            print(f"{Color.green}\t    -> {Color.reset}{Color.bold}{su} | {Color.red}SCAN DATA NOT AVAILABLE{Color.reset}")
        
        results.append(subdomain_info)
    
    subdomain_data = {
        "total": len(subdoo_list),
        "cpanel": len(cpanel_subdo),
        "non_cpanel": len(not_cpanel_subdo),
        "results": results
    }
    
    return subdomain_data

def port_scanning(target):
    """Scan ports on target"""
    os.system(f"nmap -sV {target} -o .list_nmap.txt > /dev/null")
    os.system("cat .list_nmap.txt | grep open > .list_nmap_finish.txt")
    
    ports = []
    try:
        with open(".list_nmap_finish.txt", encoding="utf-8") as file_nmap:
            port_lines = file_nmap.read().splitlines()
        
        clean("txt")
        
        print(f"{Color.bold}{Color.green}\n\t  [+] OPENED PORTS: {len(port_lines)}{Color.reset}")
        
        for p in port_lines:
            print(f"\t    {Color.green}-> {Color.reset}{Color.bold}{p}{Color.reset}")
            
            
            parts = p.split()
            if len(parts) >= 3:
                port_num = parts[0]
                state = parts[1]
                service = ' '.join(parts[2:])
                
                ports.append({
                    "port": port_num,
                    "state": state,
                    "service": service
                })
            else:
                ports.append({"raw": p})
    except FileNotFoundError:
        pass
        
    return {"total": len(ports), "ports": ports}

def scan_dir(target, user_agent=None, proxy=None):
    """Scan directories on target"""
    if user_agent:
        ug = user_agent
    else:
        ug = rangent()
        
    p = f"{os.getcwd()}/"
    
    if proxy:
        os.system(f"dirsearch -u {target} --user-agent='{ug}' --proxy='{proxy}' -o {p}.list_dir.json --format=json > /dev/null")
    else:
        os.system(f"dirsearch -u {target} --user-agent='{ug}' -o {p}.list_dir.json --format=json > /dev/null")
    
    directories = []
    
    if os.path.exists(f"{p}/.list_dir.json"):
        with open(".list_dir.json", encoding="utf-8") as dir_file:
            jdir = json.load(dir_file)
            
            if jdir:
                clean("json")
                dir_found = jdir["results"]
                list_dir_found = []
                
                for d in dir_found:
                    p_dir = d["url"]
                    status_dir = d["status"]
                    if status_dir in [200, 403, 500, 404]:
                        list_dir_found.append([status_dir, p_dir])
                
                sorted_dir = sorted(list_dir_found)
                print(f"{Color.bold}{Color.green}\n\t  [+] DIRECTORIES: {len(sorted_dir)}{Color.reset}")
                
                for d in sorted_dir:
                    status_color = Color.green if d[0] == 200 else Color.red if d[0] in [403, 500] else Color.yellow
                    print(f"{Color.green}\t    -> {Color.reset}{status_color}{str(d[0])}{Color.reset} | {Color.bold} {d[1]}{Color.reset}")
                    
                    directories.append({
                        "url": d[1],
                        "status": d[0]
                    })
            else:
                print(f"{Color.bold}{Color.red}\n\t  [-] DIRECTORIES SCANNER CANT FIND ANYTHING USEFULL{Color.reset}")
    else:
        print(f"{Color.bold}{Color.red}\n\t [-] Something wrong went running dirsearch for directory scanner{Color.reset}")
    
    return {"total": len(directories), "directories": directories}

def cms_detection(target, user_agent=None, proxy=None):
    """Detect CMS on target subdomains"""
    import requests
    
    proxies = {"http": proxy, "https": proxy} if proxy else None
    
    
    wgex = re.compile(r'(?:<meta name="generator" content="WordPress|/wp-content/)')  # WordPress
    jgex = re.compile(r'(?:<meta name="generator" content="Joomla|/media/system/js/)')  # Joomla
    druex = re.compile(r'(?:<meta name="generator" content="Drupal|/sites/all/)')  # Drupal
    moex = re.compile(r'(?:<meta name="keywords" content="moodle|/core/)')  # Moodle
    
    results = {
        "wordpress": [],
        "joomla": [],
        "drupal": [],
        "moodle": [],
        "unknown": []
    }
    
    try:
        
        with open(f"report_{target}/subdomain.txt", 'r', encoding='utf-8') as r:
            read_subdo = r.readlines()
        
        print(f"{Color.bold}{Color.green}\n\t  [+] CMS DETECTION: {len(read_subdo)} sites{Color.reset}")
        
        
        for url in read_subdo:
            url = url.strip()
            
            if user_agent:
                headers = {"User-Agent": user_agent}
            else:
                headers = {"User-Agent": rangent()}
            
            try:
                host = subprocess.check_output(f"echo {url} | httprobe", shell=True, text=True).strip()
                if not host:
                    host = f"http://{url}"
                
                response = requests.get(f'{host}', headers=headers, timeout=60, proxies=proxies)
                
                if response.status_code == 200:
                    text = response.text
                    cms_type = "unknown"
                    
                    if wgex.search(text):
                        cms_type = "wordpress"
                        print(f"{Color.green}\t    -> {Color.reset}{Color.bold}{host} | {Color.green}WordPress{Color.reset}")
                        with open(os.path.join(f"report_{target}", "wp.txt"), "a") as f:
                            f.write(f"{host}\n")
                    elif jgex.search(text):
                        cms_type = "joomla"
                        print(f"{Color.green}\t    -> {Color.reset}{Color.bold}{host} | {Color.green}Joomla{Color.reset}")
                        with open(os.path.join(f"report_{target}", "joomla.txt"), "a") as f:
                            f.write(f"{host}\n")
                    elif druex.search(text):
                        cms_type = "drupal"
                        print(f"{Color.green}\t    -> {Color.reset}{Color.bold}{host} | {Color.green}Drupal{Color.reset}")
                        with open(os.path.join(f"report_{target}", "drupal.txt"), "a") as f:
                            f.write(f"{host}\n")
                    elif moex.search(text):
                        cms_type = "moodle"
                        print(f"{Color.green}\t    -> {Color.reset}{Color.bold}{host} | {Color.green}Moodle{Color.reset}")
                        with open(os.path.join(f"report_{target}", "moodle.txt"), "a") as f:
                            f.write(f"{host}\n")
                    else:
                        print(f"{Color.green}\t    -> {Color.reset}{Color.bold}{host} | {Color.yellow}UNKNOWN CMS{Color.reset}")
                    
                    results[cms_type].append(host)
                else:
                    print(f"{Color.green}\t    -> {Color.reset}{Color.bold}{host} | {Color.red}ERROR {str(response.status_code)}{Color.reset}")
            except requests.exceptions.RequestException as e:
                print(f"{Color.green}\t    -> {Color.reset}{Color.bold}{host} | {Color.red}COULD NOT BE REACHED {e}{Color.reset}")
    except FileNotFoundError:
        print(f"{Color.red}File report_{target}/subdomain.txt not found.{Color.reset}")
    
    
    cms_counts = {
        "wordpress": len(results["wordpress"]),
        "joomla": len(results["joomla"]),
        "drupal": len(results["drupal"]),
        "moodle": len(results["moodle"]),
        "unknown": len(results["unknown"])
    }
    
    return {
        "total_scanned": len(read_subdo) if 'read_subdo' in locals() else 0,
        "cms_counts": cms_counts,
        "results": results
    }

def more_info(target, user_agent=None, proxy=None):
    """Get web technology information about target"""
    import requests
    import builtwith
    
    proxies = {"http": proxy, "https": proxy} if proxy else None
    results = []
    
    try:
        with open(f"report_{target}/subdomain.txt", 'r', encoding='utf-8') as r:
            read_subdo = r.readlines()
        
        print(f"{Color.bold}{Color.green}\n\t  [+] WEB TECHNOLOGY: {len(read_subdo)} sites{Color.reset}")
        output_file_path = f"report_{target}/subdomain_with_tech.txt"
        
        with open(output_file_path, 'w', encoding='utf-8') as output_file:
            for url in read_subdo:
                url_mentah = url.strip()
                
                try:
                    url = subprocess.check_output(f"echo {url.strip()} | httprobe", shell=True, text=True).strip()
                    if not url:
                        url = f"http://{url_mentah}"
                    
                    technologies = []
                    status = "success"
                    status_code = None
                    error = None
                    
                    try:
                        if user_agent:
                            headers = {"User-Agent": user_agent}
                        else:
                            headers = {"User-Agent": rangent()}
                        
                        
                        r = requests.get(url, headers=headers, timeout=20, proxies=proxies)
                        status_code = r.status_code
                        
                        if r.status_code == 200:
                            data = builtwith.builtwith(url)
                            keys_of_interest = ['programming-language', 'cms', 'web-servers', 'javascript-frameworks', 'web-frameworks']
                            tech_list = [tech for key in keys_of_interest if key in data for tech in data[key]]
                            
                            # Add Laravel detection
                            if 'XSRF-TOKEN' in r.cookies or 'laravel_session' in r.cookies:
                                tech_list.append("Laravel")
                            
                            technologies = tech_list
                            technologies_str = " | ".join(technologies) if technologies else f"{Color.red}No technology detected{Color.reset}"
                        else:
                            status = "error"
                            error = f"HTTP {r.status_code}"
                            technologies_str = f"{Color.red}Error code: {r.status_code}{Color.reset}"
                            
                    except requests.exceptions.Timeout:
                        status = "timeout"
                        error = "Request timeout"
                        technologies_str = f"{Color.red}Timeout{Color.reset}"
                    except ConnectionError as e:
                        status = "connection_error"
                        error = str(e)
                        technologies_str = f"{Color.red}Network error: {str(e)}{Color.reset}"
                    except requests.exceptions.RequestException as e:
                        status = "request_error"
                        error = str(e)
                        technologies_str = f"{Color.red}Host Offline{Color.reset}"
                    
                    print(f"{Color.green}\t    -> {Color.reset}{Color.bold}{url} {Color.reset}| {Color.bold}{Color.green}[ {technologies_str}{Color.green} ]{Color.reset}")
                    
                    
                    output_file.write(f"{url} | {technologies_str}\n")
                    
                    
                    results.append({
                        "url": url,
                        "status": status,
                        "status_code": status_code,
                        "error": error,
                        "technologies": technologies
                    })
                except Exception as e:
                    print(f"{Color.red}Error processing {url_mentah}: {str(e)}{Color.reset}")
                    results.append({
                        "url": url_mentah,
                        "status": "processing_error",
                        "error": str(e)
                    })
    except FileNotFoundError:
        print(f"{Color.red}File report_{target}/subdomain.txt not found.{Color.reset}")
    except KeyboardInterrupt:
        print(f"{Color.bold}[!] Keyboard Interrupt\n[!] Exit ... {Color.reset}")
    
    return {
        "total": len(results),
        "results": results
    }

def run_scan(scan_id, target, scan_type, user_agent=None, proxy=None):
    """Run a specific scan and update its status"""
    try:
        start_time = time.time()
        
        
        active_scans[scan_id]["status"] = "running"
        
        
        if scan_type == "waf":
            active_scans[scan_id]["result"] = waf_scanning(target)
        elif scan_type == "subdomain":
            active_scans[scan_id]["result"] = subdo_scanning(target)
        elif scan_type == "port":
            active_scans[scan_id]["result"] = port_scanning(target)
        elif scan_type == "directory":
            active_scans[scan_id]["result"] = scan_dir(target, user_agent, proxy)
        elif scan_type == "cms":
            active_scans[scan_id]["result"] = cms_detection(target, user_agent, proxy)
        elif scan_type == "technology":
            active_scans[scan_id]["result"] = more_info(target, user_agent, proxy)
        elif scan_type == "full":
            
            waf_result = waf_scanning(target)
            subdomain_result = subdo_scanning(target)
            port_result = port_scanning(target)
            directory_result = scan_dir(target, user_agent, proxy)
            cms_result = cms_detection(target, user_agent, proxy)
            tech_result = more_info(target, user_agent, proxy)
            
            active_scans[scan_id]["result"] = {
                "waf": waf_result,
                "subdomain": subdomain_result,
                "port": port_result,
                "directory": directory_result,
                "cms": cms_result,
                "technology": tech_result
            }
        
        
        end_time = time.time()
        duration = end_time - start_time
        
        
        active_scans[scan_id]["status"] = "completed"
        active_scans[scan_id]["completion_time"] = datetime.now().isoformat()
        active_scans[scan_id]["duration"] = duration
        
        
        result_file = os.path.join(app.config['SCAN_RESULTS_PATH'], f"{scan_id}.json")
        with open(result_file, 'w') as f:
            json.dump(active_scans[scan_id], f, indent=2)
        
    except Exception as e:
        active_scans[scan_id]["status"] = "failed"
        active_scans[scan_id]["error"] = str(e)
        print(f"Error in scan {scan_id}: {str(e)}")

# ---- API Routes ----

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new scan"""
    data = request.get_json()
    
    if not data or 'target' not in data:
        return jsonify({"error": "Target is required"}), 400
    
    target = data.get('target')
    scan_type = data.get('scan_type', 'full')  
    user_agent = data.get('user_agent')
    proxy = data.get('proxy')
    
    
    valid_scan_types = ['waf', 'subdomain', 'port', 'directory', 'cms', 'technology', 'full']
    if scan_type not in valid_scan_types:
        return jsonify({"error": f"Invalid scan type. Must be one of: {', '.join(valid_scan_types)}"}), 400
    
    
    scan_id = f"{int(time.time())}_{target.replace('.', '_')}"
    
    
    scan_info = {
        "id": scan_id,
        "target": target,
        "scan_type": scan_type,
        "status": "queued",
        "request_time": datetime.now().isoformat(),
        "user_agent": user_agent,
        "proxy": proxy
    }
    
    
    active_scans[scan_id] = scan_info
    
    
    scan_thread = threading.Thread(
        target=run_scan,
        args=(scan_id, target, scan_type, user_agent, proxy)
    )
    scan_thread.daemon = True
    scan_thread.start()
    
    return jsonify({
        "message": f"Scan started for {target}",
        "scan_id": scan_id,
        "scan_info": scan_info
    })


@app.route('/api/scans', methods=['GET'])
def list_scans():
    """List all scans"""
    
    scans = list(active_scans.values())
    
    
    for filename in os.listdir(app.config['SCAN_RESULTS_PATH']):
        if filename.endswith('.json'):
            scan_id = filename[:-5]  
            if scan_id not in active_scans:
                file_path = os.path.join(app.config['SCAN_RESULTS_PATH'], filename)
                with open(file_path, 'r') as f:
                    scan_data = json.load(f)
                scans.append(scan_data)
    
    return jsonify({
        "total": len(scans),
        "scans": scans
    })


@app.route('/api/scan/<scan_id>', methods=['GET', 'DELETE'])
def handle_scan(scan_id):
    if request.method == 'GET':
        """Get the status of a scan"""
        if scan_id in active_scans:
            return jsonify(active_scans[scan_id])

        
        result_file = os.path.join(app.config['SCAN_RESULTS_PATH'], f"{scan_id}.json")
        if os.path.exists(result_file):
            with open(result_file, 'r') as f:
                scan_data = json.load(f)
            return jsonify(scan_data)

        return jsonify({"error": "Scan not found"}), 404

    elif request.method == 'DELETE':
        """Delete a scan"""
        if scan_id in active_scans:
            
            if active_scans[scan_id]["status"] in ["queued", "running"]:
                return jsonify({"error": "Cannot delete an active scan"}), 400

            
            del active_scans[scan_id]

        
        result_file = os.path.join(app.config['SCAN_RESULTS_PATH'], f"{scan_id}.json")
        if os.path.exists(result_file):
            os.remove(result_file)

        return jsonify({"message": "Scan deleted"})

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "ok",
        "timestamp": datetime.now().isoformat(),
        "active_scans": len([s for s in active_scans.values() if s["status"] in ["queued", "running"]])
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=3000)
