from ..models import ShareableScan
from datetime import datetime, timedelta
from django.utils import timezone

def get_shareable_scan(share_id):
    try:
        share_scan = ShareableScan.objects.get(id=share_id, is_active=True, expires_at__gt=timezone.now())
        
        # update access count
        share_scan.access_count += 1
        share_scan.save()
        
        return {
            'scan_id': share_scan.scan_id,
            'target': share_scan.target,
            'scan_type': share_scan.scan_type,
            'created_by': share_scan.created_by.username,
            'access_count': share_scan.access_count
        }
    except ShareableScan.DoesNotExist:
        return None
    except Exception as e:
        print(f"Error getting shareable scan from DB: {e}")
        # Backup if something wrong with db, so it will get data from json file
        # share_file = os.path.join(SCAN_RESULTS_PATH, 'shareable_scans.json')
        # if not os.path.exists(share_file):
        #     return None
        
        # with open(share_file, 'r') as f:
        #     share_data = json.load(f)
        
        # share_id_str = str(share_id)  # -> str
        # if share_id_str in share_data:
        #     scan_data = share_data[share_id_str]
            
        #     # check expiry
        #     try:
        #         expiry_date = datetime.fromisoformat(scan_data['expires_at'].replace('Z', '+00:00'))
        #         if timezone.now() < expiry_date and scan_data['is_active']:
        #             # update access count
        #             scan_data['access_count'] += 1
        #             share_data[share_id_str] = scan_data
                    
        #             with open(share_file, 'w') as f:
        #                 json.dump(share_data, f, indent=2)
                    
        #             return scan_data
        #     except Exception as e:
        #         print(f"Error parsing expiry date: {e}")
        
        # return None
        #### FOR DEVELOPMENT ONLY