from ..lib.utility import clean
from ..exlib.safe_shell import  safe_shell_exec
import shlex, os

def port_scanning(target):
    try:
        # Safe nmap execution
        result = safe_shell_exec(f"nmap -sV {shlex.quote(target)} -oN .list_nmap.txt")
        
        if not result['success']:
            return {"error": "Port scan failed", "ports": []}
        
        # Parse nmap results
        ports = []
        if os.path.exists(".list_nmap.txt"):
            with open(".list_nmap.txt", "r", encoding="utf-8") as f:
                for line in f:
                    if 'open' in line and 'tcp' in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            ports.append({
                                "port": parts[0].split('/')[0],
                                "state": parts[1],
                                "service": ' '.join(parts[2:])
                            })
        
        clean("txt")
        return {"total": len(ports), "ports": ports}
        
    except Exception as e:
        return {"error": f"Port scanning failed: {str(e)}", "ports": []}
