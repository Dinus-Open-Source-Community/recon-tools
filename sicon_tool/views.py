import os
import json
import time
import threading
import re
from datetime import datetime
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.utils import timezone
from django.views import View
from .models import ShareableScan
from lib.color import Color
from lib.utility import create_report_folder, clean, safe_remove
from lib.random_ag import rangent
from lib.distro import distro
from .shareablelib.get_share import get_shareable_scan
from .shareablelib.create_revoke_share import create_shareable_scan, revoke_shareable_scan; 
from .exlib.better_httprobe import safe_httprobe
from .exlib.safe_shell import safe_shell_exec
from .scannerlib.waf import waf_scanning
from .scannerlib.subdo import subdo_scanning
from .scannerlib.portscanner import port_scanning
from .scannerlib.dirscanner import scan_dir
from .scannerlib.technology import more_info
from .scannerlib.cms import cms_detection

# Global dictionary to track active scans
active_scans = {}
SCAN_RESULTS_PATH = getattr(settings, 'SCAN_RESULTS_PATH', 'sicon_tool/scan_results')

os.makedirs(SCAN_RESULTS_PATH, exist_ok=True)

def get_shareable_scans_db():
    try:
        return ShareableScan.objects.filter(is_active=True, expires_at__gt=datetime.now())
    except Exception as e:
        return f"Error: {e}"

def sicon_tool(request):
    return render(request, 'sicon/sicon_tool.html')

# === SCAN MANAGEMENT ===

def run_scan(scan_id, target, scan_type, user_agent=None, proxy=None):
    try:
        start_time = time.time()
        
        # Update scan status
        active_scans[scan_id]["status"] = "running"
        
        # Execute the requested scan
        if scan_type == "waf":
            result = waf_scanning(target)
        elif scan_type == "subdomain":
            result = subdo_scanning(target)
        elif scan_type == "port":
            result = port_scanning(target)
        elif scan_type == "directory":
            result = scan_dir(target, user_agent, proxy)
        elif scan_type == "cms":
            result = cms_detection(target, user_agent, proxy)
        elif scan_type == "technology":
            result = more_info(target, user_agent, proxy)
        elif scan_type == "full":
            # Run all scans
            result = {
                "waf": waf_scanning(target),
                "subdomain": subdo_scanning(target),
                "port": port_scanning(target),
                "directory": scan_dir(target, user_agent, proxy),
                "cms": cms_detection(target, user_agent, proxy),
                "technology": more_info(target, user_agent, proxy)
            }
        else:
            result = {"error": f"Unknown scan type: {scan_type}"}
        
        # Update scan completion
        end_time = time.time()
        duration = end_time - start_time
        
        active_scans[scan_id].update({
            "status": "completed",
            "result": result,
            "completion_time": datetime.now().isoformat(),
            "duration": round(duration, 2)
        })
        
        # Save results to file
        result_file = os.path.join(SCAN_RESULTS_PATH, f"{scan_id}.json")
        with open(result_file, 'w') as f:
            json.dump(active_scans[scan_id], f, indent=2)
        
    except Exception as e:
        active_scans[scan_id].update({
            "status": "failed",
            "error": str(e)
        })

# === API VIEWS ===
@csrf_exempt
def start_scan_api(request):
    if request.method != 'POST':
        return JsonResponse({"error": "Method not allowed"}, status=405)
    
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)
    
    target = data.get('target', '').strip()
    if not target:
        return JsonResponse({"error": "Target is required"}, status=400)
    
    # Validate target format (basic validation)
    if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
        return JsonResponse({"error": "Invalid target format"}, status=400)
    
    scan_type = data.get('scan_type', 'full')
    user_agent = data.get('user_agent')
    proxy = data.get('proxy')
    
    # Validate scan type
    valid_scan_types = ['waf', 'subdomain', 'port', 'directory', 'cms', 'technology', 'full']
    if scan_type not in valid_scan_types:
        return JsonResponse({
            "error": f"Invalid scan type. Must be one of: {', '.join(valid_scan_types)}"
        }, status=400)
    
    # Generate session-based identifier for anonymous users
    if request.user.is_authenticated:
        user_id = request.user.username
    else:
        # Use session key for anonymous users
        if not request.session.session_key:
            request.session.create()
        user_id = f"anonymous_{request.session.session_key}"
    
    # Create scan ID with uid
    scan_id = f"{int(time.time())}_{target.replace('.', '_')}_{user_id}"
    
    # Initialize scan info with owner
    scan_info = {
        "id": scan_id,
        "target": target,
        "scan_type": scan_type,
        "status": "queued",
        "request_time": datetime.now().isoformat(),
        "user_agent": user_agent,
        "proxy": proxy,
        "owner": user_id,
        "is_shareable": False,
        "share_token": None,
        "user_type": "authenticated" if request.user.is_authenticated else "anonymous"
    }
    
    active_scans[scan_id] = scan_info
    
    # Start scan in background thread
    scan_thread = threading.Thread(
        target=run_scan,
        args=(scan_id, target, scan_type, user_agent, proxy)
    )
    scan_thread.daemon = True
    scan_thread.start()
    
    return JsonResponse({
        "message": f"Scan started for {target}",
        "scan_id": scan_id,
        "scan_info": scan_info
    })

@csrf_exempt
def list_scans_api(request):
    if request.method != 'GET':
        return JsonResponse({"error": "Method not allowed"}, status=405)
    
    # Determine uid
    if request.user.is_authenticated:
        user_id = request.user.username
    else:
        if not request.session.session_key:
            # No session, return empty
            return JsonResponse({"total": 0, "scans": []})
        user_id = f"anonymous_{request.session.session_key}"
    
    scans = []
    
    # scan filter
    for scan in active_scans.values():
        if scan.get('owner') == user_id:
            scans.append(scan)
        elif scan.get('is_shareable', False) and request.user.is_authenticated:
            # only authenticated users can see shared scan 
            scans.append(scan)
    
    try:
        for filename in os.listdir(SCAN_RESULTS_PATH):
            if filename.endswith('.json') and not filename.startswith('shareable_'):
                scan_id = filename[:-5]
                if scan_id not in active_scans:
                    file_path = os.path.join(SCAN_RESULTS_PATH, filename)
                    with open(file_path, 'r') as f:
                        scan_data = json.load(f)
                    if scan_data.get('owner') == user_id:
                        scans.append(scan_data)
                    elif scan_data.get('is_shareable', False) and request.user.is_authenticated:
                        scans.append(scan_data)
    except Exception as e:
        print(f"Error loading scan files: {e}")
    
    return JsonResponse({
        "total": len(scans),
        "scans": scans
    })

@csrf_exempt
def scan_status_api(request, scan_id):
    if request.method == 'GET':
        # Determine uid
        if request.user.is_authenticated:
            user_id = request.user.username
        else:
            if not request.session.session_key:
                return JsonResponse({"error": "Access denied - no session"}, status=403)
            user_id = f"anonymous_{request.session.session_key}"
        
        # check in active scans
        if scan_id in active_scans:
            scan_data = active_scans[scan_id]
            
            if (scan_data.get('owner') != user_id and 
                not scan_data.get('is_shareable', False)):
                return JsonResponse({"error": "Access denied"}, status=403)
            
            return JsonResponse(scan_data)
        
        # Check completed scans
        result_file = os.path.join(SCAN_RESULTS_PATH, f"{scan_id}.json")
        if os.path.exists(result_file):
            try:
                with open(result_file, 'r') as f:
                    scan_data = json.load(f)
                
                # Access control
                if (scan_data.get('owner') != user_id and 
                    not scan_data.get('is_shareable', False)):
                    return JsonResponse({"error": "Access denied"}, status=403)
                
                return JsonResponse(scan_data)
            except Exception as e:
                return JsonResponse({"error": f"Error reading scan file: {str(e)}"}, status=500)
        
        return JsonResponse({"error": "Scan not found"}, status=404)
    
    elif request.method == 'DELETE':
        # Determine uid
        if request.user.is_authenticated:
            user_id = request.user.username
        else:
            if not request.session.session_key:
                return JsonResponse({"error": "Access denied - no session"}, status=403)
            user_id = f"anonymous_{request.session.session_key}"
        
        # only the owner can delete
        if scan_id in active_scans:
            if active_scans[scan_id].get('owner') != user_id:
                return JsonResponse({"error": "Access denied"}, status=403)
                
            if active_scans[scan_id]["status"] in ["queued", "running"]:
                return JsonResponse({"error": "Cannot delete an active scan"}, status=400)
            del active_scans[scan_id]
        
        # delete result file
        result_file = os.path.join(SCAN_RESULTS_PATH, f"{scan_id}.json")
        if os.path.exists(result_file):
            try:
                with open(result_file, 'r') as f:
                    scan_data = json.load(f)
                
                if scan_data.get('owner') != user_id:
                    return JsonResponse({"error": "Access denied"}, status=403)
                
                os.remove(result_file)
            except Exception as e:
                return JsonResponse({"error": f"Error deleting scan file: {str(e)}"}, status=500)
        
        return JsonResponse({"message": "Scan deleted"})
    
    else:
        return JsonResponse({"error": "Method not allowed"}, status=405)

# ==== Share link === #
@csrf_exempt
def create_share_link_api(request, scan_id):
    if request.method != 'POST':
        return JsonResponse({"error": "Method not allowed"}, status=405)
    
    try:
        data = json.loads(request.body)
        expiry_days = data.get('expiry_days', 7)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)
    
    # Determine uid
    if request.user.is_authenticated:
        user_id = request.user.username
    else:
        if not request.session.session_key:
            return JsonResponse({"error": "Access denied - no session"}, status=403)
        user_id = f"anonymous_{request.session.session_key}"
    
    # checking if the scan result is exists for user
    scan_data = None
    if scan_id in active_scans:
        scan_data = active_scans[scan_id]
    else:
        result_file = os.path.join(SCAN_RESULTS_PATH, f"{scan_id}.json")
        if os.path.exists(result_file):
            with open(result_file, 'r') as f:
                scan_data = json.load(f)
    
    if not scan_data:
        return JsonResponse({"error": "Scan not found"}, status=404)
    
    # Access control
    if scan_data.get('owner') != user_id:
        return JsonResponse({"error": "Access denied"}, status=403)
    
    # anonym user cant created shared link
    if not request.user.is_authenticated:
        return JsonResponse({"error": "Anonymous users cannot create shareable links"}, status=403)
    
    # create shareable link
    share_token = create_shareable_scan(
        scan_id=scan_id,
        target=scan_data['target'],
        scan_type=scan_data['scan_type'],
        user=request.user,
        expiry_days=expiry_days
    )
    
    # Update data scan for mark shareable link
    scan_data['is_shareable'] = True
    scan_data['share_token'] = share_token
    
    # save update
    if scan_id in active_scans:
        active_scans[scan_id] = scan_data
    else:
        result_file = os.path.join(SCAN_RESULTS_PATH, f"{scan_id}.json")
        with open(result_file, 'w') as f:
            json.dump(scan_data, f, indent=2)
    
    share_url = f"{request.scheme}://{request.get_host()}/api/scans/shared/{share_token}/"
    
    return JsonResponse({
        "message": "Shareable link created",
        "share_token": share_token,
        "share_url": share_url,
        "expires_in": f"{expiry_days} days"
    })
    
def shared_scan_page(request, share_token):
    return render(request, 'sicon/shared_scan.html', {
        'share_token': share_token
    })
    
@csrf_exempt
@login_required
def revoke_share_link_api(request, scan_id):
    if request.method != 'POST':
        return JsonResponse({"error": "Method not allowed"}, status=405)
    
    share_token = None
    scan_data = None
    
    if scan_id in active_scans:
        scan_data = active_scans[scan_id]
        share_token = scan_data.get('share_token')
    else:
        result_file = os.path.join(SCAN_RESULTS_PATH, f"{scan_id}.json")
        if os.path.exists(result_file):
            with open(result_file, 'r') as f:
                scan_data = json.load(f)
            share_token = scan_data.get('share_token')
    
    if not share_token:
        return JsonResponse({"error": "No shareable link found for this scan"}, status=404)
    
    user_id = request.user.username
    if scan_data.get('owner') != user_id:
        return JsonResponse({"error": "Access denied"}, status=403)
    
    success = revoke_shareable_scan(share_token, request.user)
    
    if success:
        if scan_data:
            scan_data['is_shareable'] = False
            scan_data['share_token'] = None
            
            if scan_id in active_scans:
                active_scans[scan_id] = scan_data
            else:
                result_file = os.path.join(SCAN_RESULTS_PATH, f"{scan_id}.json")
                with open(result_file, 'w') as f:
                    json.dump(scan_data, f, indent=2)
        
        return JsonResponse({"message": "Shareable link revoked"})
    else:
        return JsonResponse({"error": "Failed to revoke shareable link"}, status=500)

@csrf_exempt
def shared_scan_api(request, share_token):
    if request.method != 'GET':
        return JsonResponse({"error": "Method not allowed"}, status=405)
    
    print(f"Attempting to access shared scan with token: {share_token}")  # debug
    
    # get shareable data
    share_data = get_shareable_scan(share_token)
    if not share_data:
        print(f"Share token not found or expired: {share_token}")  # debug
        return JsonResponse({"error": "Invalid or expired share link"}, status=404)
    
    scan_id = share_data['scan_id']
    print(f"Found share data for scan: {scan_id}")  # debug
    
    # geting scan res
    scan_result = None
    if scan_id in active_scans:
        scan_result = active_scans[scan_id]
        print(f"Scan found in active scans: {scan_id}")  # debug
    else:
        result_file = os.path.join(SCAN_RESULTS_PATH, f"{scan_id}.json")
        print(f"Looking for scan file: {result_file}")  # debug
        if os.path.exists(result_file):
            try:
                with open(result_file, 'r') as f:
                    scan_result = json.load(f)
                print(f"Scan loaded from file: {scan_id}")  # debug
            except Exception as e:
                print(f"Error loading scan file: {e}")  # debug
                return JsonResponse({"error": "Error loading scan results"}, status=500)
    
    if not scan_result:
        print(f"Scan results not found for: {scan_id}")  # debug
        return JsonResponse({"error": "Scan results not found"}, status=404)
    
    # shareable mark
    scan_result['is_shareable'] = True
    scan_result['accessed_via_share'] = True
    
    scan_result['shared_info'] = {
        'accessed_via': 'share_link',
        'share_creator': share_data['created_by'],
        'access_count': share_data['access_count'],
        'note': 'This scan was accessed via a shareable link'
    }
    
    print(f"Successfully returning shared scan: {scan_id}")  # debug
    return JsonResponse(scan_result)

@csrf_exempt
def health_check_api(request):
    if request.method != 'GET':
        return JsonResponse({"error": "Method not allowed"}, status=405)
    
    active_count = len([s for s in active_scans.values() if s["status"] in ["queued", "running"]])
    
    return JsonResponse({
        "status": "ok",
        "timestamp": datetime.now().isoformat(),
        "active_scans": active_count
    })