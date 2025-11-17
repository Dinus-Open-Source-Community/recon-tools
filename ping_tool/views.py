from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from multiping import MultiPing
import socket
import re

def ping_tool(request):
    return render(request, 'ping/ping.html')

@csrf_exempt
def ping_api(request):
    if request.method == 'POST':
        try:
            target = request.POST.get('target', '').strip()
            count = int(request.POST.get('count', 4))
            timeout = int(request.POST.get('timeout', 2))
            
            if not target:
                return JsonResponse({'success': False, 'error': 'Target tidak boleh kosong'})
            
            if not is_valid_target(target):
                return JsonResponse({'success': False, 'error': 'Format target tidak valid. Gunakan IP atau domain'})
            
            count = min(max(count, 1), 10)  # Min 1, Max 10
            timeout = min(max(timeout, 1), 10)  # Min 1, Max 10
            
            ping_result = perform_ping(target, count, timeout)
            
            return JsonResponse({
                'success': True, 
                'data': ping_result
            })
            
        except ValueError:
            return JsonResponse({'success': False, 'error': 'Parameter count dan timeout harus angka'})
        except Exception as e:
            return JsonResponse({'success': False, 'error': f'Terjadi kesalahan: {str(e)}'})
    
    return JsonResponse({'success': False, 'error': 'Method tidak diizinkan'})

def perform_ping(target, count=4, timeout=2):
    try:
        try:
            ip_address = socket.gethostbyname(target)
            resolved_ip = ip_address
        except socket.gaierror:
            resolved_ip = None

        results = []
        success_count = 0
        total_time = 0.0

        for i in range(count):
            mp = MultiPing([target])
            mp.send()
            responses, no_responses = mp.receive(timeout)
            # responses: dict of address -> rtt (seconds)

            print("test")
            if responses:
                # take the first responding address
                addr, rtt = next(iter(responses.items()))
                # normalize address to string (addr can be a tuple or an IP string, including IPv6)
                addr_str = addr[0] if isinstance(addr, tuple) else str(addr)
                time_ms = round(float(rtt) * 1000, 2)
                success = True
                message = f"Reply from {addr_str}: time={time_ms} ms"
            else:
                time_ms = None
                success = False
                message = "Request timed out."

            if success:
                success_count += 1
                total_time += time_ms

            results.append({
                'sequence': i + 1,
                'success': success,
                'time_ms': time_ms,
                'message': message
            })

        packet_loss = ((count - success_count) / count) * 100
        avg_time = total_time / success_count if success_count > 0 else 0

        times = [r['time_ms'] for r in results if r['time_ms'] is not None]

        summary = {
            'target': target,
            'resolved_ip': resolved_ip,
            'packets_sent': count,
            'packets_received': success_count,
            'packet_loss': round(packet_loss, 1),
            'min_time': min(times) if times else 0,
            'max_time': max(times) if times else 0,
            'avg_time': round(avg_time, 2),
            'success': success_count > 0
        }

        return {
            'results': results,
            'summary': summary
        }

    except Exception as e:
        print(e)
        raise Exception(f'Gagal melakukan ping: {str(e)}')

def is_valid_target(target):
    if not target:
        return False
    
    try:
        socket.inet_aton(target)
        return True
    except socket.error:
        pass
    
    try:
        socket.inet_pton(socket.AF_INET6, target)
        return True
    except socket.error:
        pass
    
    if '.' in target and len(target) > 3:
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(domain_pattern, target))
    
    return False