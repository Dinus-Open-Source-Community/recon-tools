from lib.utility import create_report_folder, clean, safe_remove
from ..exlib.better_httprobe import safe_httprobe
from ..exlib.safe_shell import  safe_shell_exec
import shlex, re

def waf_scanning(target):
    create_report_folder(target)
    try:
        host = safe_httprobe(target)
        result = safe_shell_exec(f"wafw00f {shlex.quote(host)}")
        
        if not result['success']:
            return {
                "detected": False, 
                "name": None, 
                "error": result.get('error', 'Unknown error'),
                "output": "WAF detection failed to execute"
            }
        
        waf_output = result['stdout']
        scan_result = {
            "detected": False,
            "name": None,
            "output": clean_waf_output(waf_output)
        }
        
        # Parse WAF detection results
        if "is behind" in waf_output:
            match = re.search(r'is behind\s+(.+?)\s+\(', waf_output)
            if match:
                wafname = match.group(1).strip()
                scan_result["detected"] = True
                scan_result["name"] = wafname
        elif "No WAF detected" in waf_output or "No WAF detected by the generic detection" in waf_output:
            scan_result["detected"] = False
            scan_result["name"] = "No WAF detected"
        elif "The site seems to be behind" in waf_output:
            scan_result["detected"] = True
            scan_result["name"] = "Unknown WAF"
            
        return scan_result
        
    except Exception as e:
        return {
            "detected": False, 
            "name": None, 
            "error": str(e),
            "output": f"WAF scanning error: {str(e)}"
        }

def clean_waf_output(output):
    # Remove ANSI color codes
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    cleaned = ansi_escape.sub('', output)
    
    # Extract only relevant parts
    lines = cleaned.split('\n')
    relevant_lines = []
    
    for line in lines:
        if any(keyword in line for keyword in [
            'Checking', 'WAF', 'detected', 'behind', 'Number of requests', 'Generic Detection'
        ]):
            relevant_lines.append(line.strip())
    
    return '\n'.join(relevant_lines) if relevant_lines else "No WAF information available"
