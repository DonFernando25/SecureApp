from django.contrib.auth import login, authenticate,logout
from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from supabase_config import supabase
from .utils import hash_password, check_password
from django.contrib import messages
from supabase.lib.client_options import SupabaseException





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

        except SupabaseException as e:
            messages.error(request, f"Error al registrar usuario: {str(e)}")

    return render(request, 'register.html')

@login_required
def home_view(request):
    return render(request, 'home.html')



def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        response = supabase.table('users').select("*").eq("username", username).execute()
        if response.data:
            user = response.data[0] 
            if check_password(password, user["password"]):
                request.session['user_id'] = user['id'] 
                messages.success(request, "Inicio de sesión exitoso.")
                return redirect('home')
            else:
                messages.error(request, "Contraseña incorrecta.")
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