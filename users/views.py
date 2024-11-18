from django.contrib.auth import login, authenticate
from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse




def register(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect('home')
    else:
        form = UserCreationForm()
    return render(request, 'users/register.html', {'form': form})


@login_required
def home_view(request):
    return render(request, 'home.html')



def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password") 
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('home')  
        else:
            return HttpResponse("Credenciales inválidas.", status=401)
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