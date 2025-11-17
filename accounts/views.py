from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.forms import UserCreationForm
from django.contrib import messages
from django.contrib.auth.decorators import login_required

def register(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            username = form.cleaned_data.get('username')
            messages.success(request, f'Akun berhasil dibuat untuk {username}!')
            login(request, user)
            return redirect('dashboard')
    else:
        form = UserCreationForm()
    
    return render(request, 'register.html', {'form': form})

# Custom logout view
def custom_logout(request):
    if request.method == 'POST':
        logout(request)
        messages.success(request, 'Anda telah berhasil logout.')
        return redirect('home')
    else:
        # Jika diakses dengan GET, redirect ke home
        return redirect('home')