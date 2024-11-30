from django.contrib.auth import login, authenticate,logout
from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from supabase_config import supabase
from .utils import hash_password, check_password
from django.contrib import messages
from datetime import datetime, timedelta
from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError
from django.contrib.auth.hashers import make_password





def register_user(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        try:
            validate_username(username)
        except ValidationError as e:
            messages.error(request, f"Error en el nombre de usuario: {e.message}")
            return render(request, 'register.html')
        try:
            validate_password(password)
        except ValidationError as e:
            messages.error(request, f"Error en la contraseña: {e.message}")
            return render(request, 'register.html')
        hashed_password = make_password(password)
        try:
            response = supabase.table('users').insert({
                "username": username,
                "password": hashed_password,
                "failed_attempts": 0,
                "locked_until": None
            }).execute()
            if response.error: 
                messages.error(request, f"Error al registrar usuario: {response.error.message}")
            elif response.data:  
                messages.success(request, "Usuario registrado exitosamente. Ahora puedes iniciar sesión.")
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
        try:
            validate_username(username)
        except ValidationError as e:
            messages.error(request, f"Error en el nombre de usuario: {e.message}")
            return render(request, 'login.html')
        try:
            validate_password(password)
        except ValidationError as e:
            messages.error(request, f"Error en la contraseña: {e.message}")
            return render(request, 'login.html')
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
                request.session.cycle_key()
                request.session['user_id'] = user['id']
                request.session.set_expiry(3600)  
                messages.success(request, "Inicio de sesión exitoso.")
                return redirect('home')
            else:
                failed_attempts = user['failed_attempts'] + 1
                if failed_attempts >= 3:
                    locked_until = datetime.utcnow() + timedelta(days=3)
                    supabase.table('users').update({
                        "failed_attempts": failed_attempts,
                        "locked_until": locked_until.isoformat()
                    }).eq("username", username).execute()
                    messages.error(request, "Has alcanzado el límite de intentos. La cuenta está bloqueada por 3 días.")
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

def validate_username(username):
    validator = RegexValidator(
        regex=r'^\w+$',
        message="El nombre de usuario solo puede contener letras, números y guiones bajos."
    )
    validator(username)


def validate_password(password):
    if len(password) < 8:
        raise ValidationError("La contraseña debe tener al menos 8 caracteres.")
    if not any(char.isdigit() for char in password):
        raise ValidationError("La contraseña debe contener al menos un número.")
    if not any(char.isalpha() for char in password):
        raise ValidationError("La contraseña debe contener al menos una letra.")