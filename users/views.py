from django.contrib.auth import login, authenticate,logout
from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from supabase_config import supabase
from .utils import hash_password, check_password
from django.contrib import messages
from datetime import datetime, timedelta





def register_user(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        hashed_password = hash_password(password)
        try:
            response = supabase.table('users').insert({
                "username": username,
                "password": hashed_password,
            }).execute()
            if response.data:
                messages.success(request, "Usuario registrado exitosamente.")
                return redirect('login')
            else:
                messages.error(request, "No se pudo registrar el usuario. Inténtalo de nuevo.")
        except Exception as e:
            messages.error(request, f"Error al registrar usuario: {str(e)}")
    return render(request, 'register.html')



def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        response = supabase.table('users').select("*").eq("username", username).execute()
        if response.data:
            user = response.data[0]
            if user['locked_until'] and datetime.strptime(user['locked_until'], '%Y-%m-%dT%H:%M:%S.%f') > datetime.utcnow():
                messages.error(request, "La cuenta está bloqueada. Intenta nuevamente más tarde.")
                return render(request, 'login.html')
            if check_password(password, user["password"]):
                supabase.table('users').update({
                    "failed_attempts": 0,
                    "locked_until": None
                }).eq("username", username).execute()
                request.session['user_id'] = user['id']
                messages.success(request, "Inicio de sesión exitoso.")
                return redirect('home')
            else:
                failed_attempts = user['failed_attempts'] + 1
                if failed_attempts >= 3:
                    locked_until = datetime.utcnow() + timedelta(minutes=5)
                    supabase.table('users').update({
                        "failed_attempts": failed_attempts,
                        "locked_until": locked_until.isoformat()
                    }).eq("username", username).execute()
                    messages.error(request, "Has alcanzado el límite de intentos. La cuenta está bloqueada por 5 minutos.")
                else:
                    supabase.table('users').update({
                        "failed_attempts": failed_attempts
                    }).eq("username", username).execute()
                    messages.error(request, f"Contraseña incorrecta. Intentos restantes: {3 - failed_attempts}")
        else:
            messages.error(request, "Usuario no encontrado.")
    return render(request, 'login.html')


def home_view(request):
    if 'user_id' not in request.session:
        return redirect('login')
    return render(request, 'home.html')


def logout_view(request):
    logout(request)
    messages.success(request, "Sesión cerrada exitosamente.")
    return redirect('login')