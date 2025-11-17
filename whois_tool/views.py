import whois
import json
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views import View

def whois_lookup(request):
    return render(request, 'whois/whois_lookup.html')

@csrf_exempt
def whois_api(request):
    if request.method == 'POST':
        try:
            if request.content_type == 'application/json':
                data = json.loads(request.body)
                domain = data.get('domain', '').strip().lower()
            else:
                domain = request.POST.get('domain', '').strip().lower()
            
            print(f"Looking up domain: {domain}")  # debug print
            
            if not domain:
                return JsonResponse({'success': False, 'error': 'Domain tidak boleh kosong'})
            
            if '.' not in domain:
                return JsonResponse({'success': False, 'error': 'Format domain tidak valid'})
            
            domain = domain.replace('http://', '').replace('https://', '').replace('www.', '').split('/')[0]
            
            try:
                domain_info = whois.whois(domain)
                print(f"WHOIS result: {domain_info}")  # debug print
            except Exception as e:
                return JsonResponse({'success': False, 'error': f'Gagal melakukan lookup WHOIS: {str(e)}'})
            
            result = {
                'domain': domain,
                'registrar': getattr(domain_info, 'registrar', 'Tidak tersedia'),
                'creation_date': format_date(getattr(domain_info, 'creation_date', None)),
                'expiration_date': format_date(getattr(domain_info, 'expiration_date', None)),
                'updated_date': format_date(getattr(domain_info, 'updated_date', None)),
                'name_servers': format_name_servers(getattr(domain_info, 'name_servers', [])),
                'status': format_status(getattr(domain_info, 'status', 'Tidak tersedia')),
                'emails': format_emails(getattr(domain_info, 'emails', [])),
                'org': getattr(domain_info, 'org', 'Tidak tersedia'),
                'country': getattr(domain_info, 'country', 'Tidak tersedia'),
            }
            
            return JsonResponse({'success': True, 'data': result})
            
        except whois.parser.PywhoisError as e:
            return JsonResponse({'success': False, 'error': f'Domain tidak ditemukan: {str(e)}'})
        except Exception as e:
            print(f"Error in whois_api: {str(e)}")  # debug print
            return JsonResponse({'success': False, 'error': f'Terjadi kesalahan server: {str(e)}'})
    
    return JsonResponse({'success': False, 'error': 'Method tidak diizinkan'})

# just helper functions
def format_date(date_value):
    if not date_value:
        return 'Tidak tersedia'
    
    if isinstance(date_value, list):
        date_value = date_value[0] if date_value else None
    
    if date_value:
        return date_value.strftime('%d-%m-%Y %H:%M:%S')
    return 'Tidak tersedia'

def format_name_servers(servers):
    if not servers:
        return ['Tidak tersedia']
    
    if isinstance(servers, list):
        return [str(s).lower() for s in servers if s]
    elif isinstance(servers, str):
        return [servers.lower()]
    else:
        return ['Tidak tersedia']

def format_status(status):
    if not status:
        return 'Tidak tersedia'
    
    if isinstance(status, list):
        return ', '.join([str(s) for s in status if s])
    return str(status)

def format_emails(emails):
    if not emails:
        return ['Tidak tersedia']
    
    if isinstance(emails, list):
        return [str(e).lower() for e in emails if e]
    elif isinstance(emails, str):
        return [emails.lower()]
    else:
        return ['Tidak tersedia']