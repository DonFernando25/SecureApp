from django.contrib.auth import login, authenticate
from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from supabase_config import supabase
from .utils import hash_password, check_password





def register_user(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        hashed_password = hash_password(password)
        
        try:
            response = supabase.table('users').insert({
                "username": username,
                "password": hashed_password
            }).execute()
            return HttpResponse("Usuario registrado con éxito.")
        except Exception as e:
            return HttpResponse(f"Error al registrar usuario: {str(e)}", status=500)
    
    return render(request, 'register.html')


@login_required
def home_view(request):
    return render(request, 'home.html')



def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        try:
            response = supabase.table('users').select("*").eq("username", username).execute()
            user = response.data[0] if response.data else None
            
            if user and check_password(password, user['password']):
                return HttpResponse("Inicio de sesión exitoso.")
            else:
                return HttpResponse("Credenciales inválidas.", status=401)
        except Exception as e:
            return HttpResponse(f"Error al autenticar: {str(e)}", status=500)
    
    return render(request, 'login.html')


@login_required
def sql_injection_test(request):
    if request.method == "POST":
        sql_query = request.POST.get("sql_query")
        from django.db import connection
        try:
            with connection.cursor() as cursor:
                cursor.execute(sql_query)
                results = cursor.fetchall()
            return render(request, 'sql_test.html', {'results': results})
        except Exception as e:
            return render(request, 'sql_test.html', {'error': str(e)})
    return render(request, 'sql_test.html')