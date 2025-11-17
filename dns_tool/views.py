import dns.resolver
import dns.reversename
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import socket

def nslookup_tool(request):
    return render(request, 'dns/nslookup.html')

@csrf_exempt
def nslookup_api(request):
    if request.method == 'POST':
        try:
            domain = request.POST.get('domain', '').strip()
            record_type = request.POST.get('record_type', 'A').upper()
            
            if not domain:
                return JsonResponse({'success': False, 'error': 'Domain atau IP tidak boleh kosong'})
            
            if is_ip_address(domain):
                return perform_reverse_lookup(domain)
            
            return perform_dns_lookup(domain, record_type)
            
        except Exception as e:
            return JsonResponse({'success': False, 'error': f'Terjadi kesalahan: {str(e)}'})
    
    return JsonResponse({'success': False, 'error': 'Method tidak diizinkan'})

def perform_dns_lookup(domain, record_type):
    results = []
    
    try:
        answers = dns.resolver.resolve(domain, record_type)
        
        for rdata in answers:
            result = {
                'type': record_type,
                'value': str(rdata),
                'ttl': rdata.ttl if hasattr(rdata, 'ttl') else 'N/A'
            }
            
            if record_type == 'A':
                result['ip'] = str(rdata)
                try:
                    hostname = socket.gethostbyaddr(str(rdata))[0]
                    result['reverse_dns'] = hostname
                except (socket.herror, socket.gaierror):
                    result['reverse_dns'] = 'Tidak tersedia'
            elif record_type == 'AAAA':
                result['ipv6'] = str(rdata)
            elif record_type == 'CNAME':
                result['alias'] = str(rdata)
            elif record_type == 'MX':
                result['priority'] = rdata.preference
                result['mail_server'] = str(rdata.exchange)
            elif record_type == 'TXT':
                result['text'] = str(rdata)
            elif record_type == 'NS':
                result['nameserver'] = str(rdata)
            elif record_type == 'SOA':
                result['mname'] = str(rdata.mname)
                result['rname'] = str(rdata.rname)
                result['serial'] = rdata.serial
                result['refresh'] = rdata.refresh
                result['retry'] = rdata.retry
                result['expire'] = rdata.expire
                result['minimum'] = rdata.minimum
            
            results.append(result)
            
    except dns.resolver.NoAnswer:
        return JsonResponse({'success': False, 'error': f'Tidak ada record {record_type} untuk domain tersebut'})
    except dns.resolver.NXDOMAIN:
        return JsonResponse({'success': False, 'error': 'Domain tidak ditemukan'})
    except dns.resolver.Timeout:
        return JsonResponse({'success': False, 'error': 'Timeout saat melakukan DNS lookup'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': f'Error DNS lookup: {str(e)}'})
    
    additional_info = get_additional_dns_info(domain)
    
    return JsonResponse({
        'success': True, 
        'data': {
            'domain': domain,
            'record_type': record_type,
            'results': results,
            'additional_info': additional_info,
            'lookup_type': 'DNS Lookup'
        }
    })

def perform_reverse_lookup(ip):
    try:
        # Method 1: socket.gethostbyaddr
        try:
            hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(ip)
            reverse_info = {
                'hostname': hostname,
                'aliases': aliaslist,
                'ip_addresses': ipaddrlist,
                'method': 'socket.gethostbyaddr'
            }
        except (socket.herror, socket.gaierror):
            reverse_info = {
                'hostname': 'Tidak ditemukan',
                'aliases': [],
                'ip_addresses': [ip],
                'method': 'socket - not found'
            }
        
        # Method 2: DNS PTR lookup
        ptr_record = None
        try:
            reversed_ip = dns.reversename.from_address(ip)
            ptr_answers = dns.resolver.resolve(reversed_ip, 'PTR')
            if ptr_answers:
                ptr_record = str(ptr_answers[0])
                if reverse_info['hostname'] == 'Tidak ditemukan':
                    reverse_info['hostname'] = ptr_record
                    reverse_info['method'] = 'DNS PTR lookup'
                reverse_info['ptr_record'] = ptr_record
        except:
            pass
        
        results = [{
            'type': 'PTR',
            'value': reverse_info['hostname'],
            'hostname': reverse_info['hostname'],
            'ttl': 'N/A'
        }]
        
        additional_info = {
            'lookup_type': 'Reverse DNS Lookup',
            'ip_address': ip,
            'reverse_method': reverse_info['method'],
            'aliases': reverse_info['aliases'],
            'ip_addresses': reverse_info['ip_addresses']
        }
        
        if ptr_record and ptr_record != reverse_info['hostname']:
            additional_info['ptr_record'] = ptr_record
        
        return JsonResponse({
            'success': True,
            'data': {
                'domain': ip,
                'record_type': 'PTR',
                'results': results,
                'additional_info': additional_info,
                'lookup_type': 'Reverse DNS'
            }
        })
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': f'Error reverse lookup: {str(e)}'})

def get_additional_dns_info(domain):
    info = {}
    
    try:
        # Get SOA record
        soa_answers = dns.resolver.resolve(domain, 'SOA')
        if soa_answers:
            soa_data = soa_answers[0]
            info['soa'] = {
                'mname': str(soa_data.mname),
                'rname': str(soa_data.rname),
                'serial': soa_data.serial,
                'refresh': soa_data.refresh,
                'retry': soa_data.retry,
                'expire': soa_data.expire,
                'minimum': soa_data.minimum
            }
    except:
        pass
    
    try:
        ns_answers = dns.resolver.resolve(domain, 'NS')
        info['nameservers'] = [str(ns) for ns in ns_answers]
    except:
        pass

    try:
        a_answers = dns.resolver.resolve(domain, 'A')
        info['a_records'] = [str(a) for a in a_answers]
    except:
        pass

    try:
        mx_answers = dns.resolver.resolve(domain, 'MX')
        info['mx_records'] = [f"{mx.preference} {mx.exchange}" for mx in mx_answers]
    except:
        pass
    
    return info

def is_ip_address(domain):
    domain = domain.strip()
    try:
        socket.inet_aton(domain)
        return True
    except socket.error:
        pass
    
    try:
        socket.inet_pton(socket.AF_INET6, domain)
        return True
    except socket.error:
        pass
    
    return False