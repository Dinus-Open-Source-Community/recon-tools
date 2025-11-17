from ..models import ShareableScan
from django.utils import timezone
from django.views import View
from datetime import datetime, timedelta


def create_shareable_scan(scan_id, target, scan_type, user, expiry_days=7):
    try:
        # delete old shareable scan for the samescan_id
        ShareableScan.objects.filter(scan_id=scan_id).delete()
        
        # create newone wth exp day
        expires_at = timezone.now() + timedelta(days=expiry_days)
        shareable_scan = ShareableScan.objects.create(
            scan_id=scan_id,
            target=target,
            scan_type=scan_type,
            created_by=user,
            expires_at=expires_at
        )
        
        return str(shareable_scan.id)  # return string
    except Exception as e:
        return f"Error: {e}"
        #### FOR DEVELOPMENT ONLY
        # Backup if something wrong with db, so it will save into a json file
        # share_file = os.path.join(SCAN_RESULTS_PATH, 'shareable_scans.json')
        # share_data = {}
        
        # if os.path.exists(share_file):
        #     with open(share_file, 'r') as f:
        #         share_data = json.load(f)
        
        # share_id = str(uuid.uuid4())
        # share_data[share_id] = {
        #     'scan_id': scan_id,
        #     'target': target,
        #     'scan_type': scan_type,
        #     'created_by': user.username if hasattr(user, 'username') else 'anonymous',
        #     'created_at': timezone.now().isoformat(),
        #     'expires_at': (timezone.now() + timedelta(days=expiry_days)).isoformat(),
        #     'is_active': True,
        #     'access_count': 0
        # }
        
        # with open(share_file, 'w') as f:
        #     json.dump(share_data, f, indent=2)
        
        # return share_id
        #### FOR DEVELOPMENT ONLY

def revoke_shareable_scan(share_id, user):
    try:
        share_scan = ShareableScan.objects.get(id=share_id, created_by=user)
        share_scan.is_active = False
        share_scan.save()
        return True
    except Exception as e:
        return f"Error getting shareable scan from DB: {e}"
        #### FOR DEVELOPMENT ONLY
        # Backup if something wrong with db, so it will update into a json file
        # share_file = os.path.join(SCAN_RESULTS_PATH, 'shareable_scans.json')
        # if not os.path.exists(share_file):
        #     return False
        
        # with open(share_file, 'r') as f:
        #     share_data = json.load(f)
        
        # if share_id in share_data:
        #     if share_data[share_id]['created_by'] == user.username:
        #         share_data[share_id]['is_active'] = False
        #         with open(share_file, 'w') as f:
        #             json.dump(share_data, f, indent=2)
        #         return True
        
        # return False
        #### FOR DEVELOPMENT ONLY
