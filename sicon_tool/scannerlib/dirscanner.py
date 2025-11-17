from ..exlib.safe_shell import  safe_shell_exec
from ..lib.utility import clean
from ..lib.random_ag import rangent
import json, shlex, os

def scan_dir(target, user_agent=None, proxy=None):
    try:
        ug = user_agent if user_agent else rangent()
        current_dir = os.getcwd()
        
        cmd_parts = ["dirsearch", "-u", target, f"--user-agent={ug}", "-o", f"{current_dir}/.list_dir.json", "--format=json"]
        
        if proxy:
            cmd_parts.append(f"--proxy={proxy}")
        
        result = safe_shell_exec(' '.join(shlex.quote(part) for part in cmd_parts))
        
        directories = []
        json_path = f"{current_dir}/.list_dir.json"
        
        if os.path.exists(json_path):
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    jdir = json.load(f)
                
                if jdir and "results" in jdir:
                    for d in jdir["results"]:
                        if d.get("status") in [200, 403, 500, 404]:
                            directories.append({
                                "url": d.get("url", ""),
                                "status": d.get("status", 0)
                            })
                
                clean("json")
                
            except json.JSONDecodeError:
                pass
        
        return {"total": len(directories), "directories": directories}
        
    except Exception as e:
        return {"error": f"Directory scanning failed: {str(e)}", "directories": []}
