import requests
from django.shortcuts import render, redirect,HttpResponse
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import authenticate, login
from django.core.exceptions import ObjectDoesNotExist
from .models import CustomUser
from io import BytesIO
from django.conf import settings
from django.db import IntegrityError
from django.contrib.auth.decorators import login_required
from .forms import UserLoginForm
from decimal import Decimal
#User login
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
import requests
import logging
from .models import MessageSendInfo
from django.contrib.auth import logout
# Logger setup for logging information, warnings, or errors.
logger = logging.getLogger(__name__)
from datetime import datetime
# View for user login
def user_login(request):
    from .forms import UserLoginForm  # Assuming form is in the same app
    
    if request.method == 'POST':
        form = UserLoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            user = authenticate(request, email=email, password=password)
            
            if user:
                login(request, user)
                logger.info(f"User {email} logged in successfully.")
                return redirect('dashboard')
            else:
                # Authentication failed
                logger.warning(f"Failed login attempt for email: {email}")
                form.add_error(None, "Invalid email or password.")
        else:
            logger.warning(f"Invalid form submission: {form.errors}")

    else:
        form = UserLoginForm()
    
    return render(request, 'login.html', {'form': form})

@login_required
def logout_view(request):
    logout(request)
    return redirect('login.hml')

# View for file upload page
@login_required
def user_dashboard(request):
    ip_address = request.META.get('REMOTE_ADDR', 'Unknown IP')
    coins = request.user.coins
    report_list = MessageSendInfo.objects.filter(email=request.user)
    new_message_info = None

    if request.method == 'POST':
        template_id = request.POST.get('params')
        uploaded_file = request.FILES.get('files')

        if not uploaded_file:
            return render_dashboard_with_error(request, "No file was uploaded", ip_address, coins, report_list)

        try:
            file_content = uploaded_file.read()
            final_count = remove_duplicate_and_invalid_contacts(file_content)
            api_response = send_messages_via_api(file_content, template_id)

            if api_response.status_code == 200:
                success_message = api_response.json()
                subtract_coins(request, final_count)
                new_message_info = MessageSendInfo(
                    email=request.user,
                    message_date=datetime.now(),
                    message_delivery=final_count,
                    message_send=final_count,
                    message_failed=2,
                )
                new_message_info.save()  # Saving inside the successful API response block
                print("New row added successfully!")
                return render_dashboard_with_success(request, success_message, ip_address, coins, report_list)
            else:
                error_message = f"API request failed with status code: {api_response.status_code}"
                return render_dashboard_with_error(request, error_message, ip_address, coins, report_list)
        except requests.RequestException as e:
            error_message = f"Error occurred during API request: {e}"
            return render_dashboard_with_error(request, error_message, ip_address, coins, report_list)

    return render_dashboard(request, ip_address, coins, report_list)


def render_dashboard(request, ip_address, coins, report_list):
    return render(request, 'dashboard.html', {
        'ip_address': ip_address,
        'coins': coins,
        'report_list': report_list,
    })


def render_dashboard_with_error(request, error_message, ip_address, coins, report_list):
    return render(request, 'dashboard.html', {
        'error_message': error_message,
        'ip_address': ip_address,
        'coins': coins,
        'report_list': report_list,
    })


def render_dashboard_with_success(request, success_message, ip_address, coins, report_list):
    return render(request, 'dashboard.html', {
        'success_message': success_message,
        'ip_address': ip_address,
        'coins': coins,
        'report_list': report_list,
    })



def send_messages_via_api(file_content, template_id):
    url = "13.239.113.104/sms/api/send_messages"
    files = {'contacts': BytesIO(file_content)}
    params = {'templateid': template_id}
    return requests.post(url, files=files, params=params)


'''
def user_login(request):
    if request.method == 'POST':
        form = UserLoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            user = authenticate(request, email=email, password=password)
    
            if user is not None:
                login(request, user)
                # Redirect to a success page or wherever you want
                print("yes")
                return redirect('fileupload')
            else:
                # Invalid login
                return render(request, 'login.html', {'form': form, 'error_message': 'Invalid login'})
    else:
        form = UserLoginForm()
    return render(request, 'login.html', {'form': form})
'''
#Password Reset Method
def initiate_password_reset(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = CustomUser.objects.get(email=email)
            token = default_token_generator.make_token(user)
            send_otp(email) 
            return redirect('otp_verification', email=email, token=token)
        except ObjectDoesNotExist:
            return render(request, 'password_reset.html', {'error_message': 'Email does not exist'})
    return render(request, 'password_reset.html')

def verify_otp(request, email, token):
    if request.method == 'POST':
        otp = request.POST.get('otp')
        if verify_otp_server(otp):
            return redirect('change_password', email=email, token=token)
        else:
            return render(request, 'otp_verification.html', {'error_message': 'Invalid OTP'})
    return render(request, 'otp_verification.html')

def change_password(request, email, token):
    if request.method == 'POST':
        new_password = request.POST.get('new_password')
        confirm_new_password = request.POST.get('confirm_new_password')
        if new_password == confirm_new_password:
            try:
                user = CustomUser.objects.get(email=email)
                if default_token_generator.check_token(user, token):
                    user.set_password(new_password)
                    user.save()
                    return redirect('login')
                else:
                    return render(request, 'change_password.html', {'error_message': 'Invalid or expired token'})
            except ObjectDoesNotExist:
                return render(request, 'change_password.html', {'error_message': 'Email does not exist'})
        else:
            return render(request, 'change_password.html', {'error_message': 'Passwords do not match'})
    return render(request, 'change_password.html')

def verify_otp_server(otp):
    verify_otp_url = "http://13.239.113.104/email/verify_otp"
    params = {"otp": otp}
    verify_otp_response = requests.post(verify_otp_url, params=params)
    return verify_otp_response.status_code == 200

def send_otp(email):
    otp_url = "http://13.239.113.104/email/otp"
    params = {
        "name":"otp",
        "email": email
    }
    otp_response = requests.post(otp_url, params=params)
    
    if otp_response.status_code == 200:
        print("OTP sent successfully.")
    else:
        return redirect("password_reset.html")
    
#Contact_list file
'''
@login_required
def FileUpload(request):
    return render(request, "fileShare.html")

#Whatsapp Message from Whatsapp api

@login_required
def upload_data(request):
    if request.method == 'POST':
        data = request.POST.get('params')
        uploaded_file = request.FILES.get('files')

        
        if uploaded_file:
            url = "http://192.168.29.200:3000/api/send_messages"
            files = {'contacts': uploaded_file.read()}  # Read the file content
            params = {'templateid': data}

            response = requests.post(url, files=files, params=params)

            if response.status_code == 200:
                return HttpResponse(response.json(), content_type="application/json")
            else:
                return HttpResponse(status=response.status_code)
        else:
            return HttpResponse("No file was uploaded", status=400)

    return render(request, 'fileShare.html')

#Show ip address of user on display




def display_info(request):
    print("success")
    user = request.CustomUser
    ip_address = request.META.get('REMOTE_ADDR', '')
    coins = user.coins
    print(coins)

    context = {
        'ip_address': ip_address,
        'coins': coins,
    }

    return render(request, 'fileShare.html', context)
'''
from django.shortcuts import get_object_or_404, render
from django.http import HttpResponse
from .models import Whitelist ,Blacklist

#Whitelist conde concept
def print_whitelist_file_data(request, whitelist_id):
    
    whitelist = get_object_or_404(Whitelist, id=whitelist_id)

 
    if whitelist.whitelist_phone:
        
        with whitelist.whitelist_phone.open('r') as file:
            file_contents = file.read()
        
    
        print(file_contents)

    
        return HttpResponse(f"<pre>{file_contents}</pre>")

    
    return HttpResponse("No whitelist file available.")

#Blacklist file code concept
def print_blacklist_file_data(request, blacklist_id):
    
    blacklist = get_object_or_404(Whitelist, id=blacklist_id)

 
    if blacklist.blacklist_phone:
        
        with blacklist.blacklist_phone.open('r') as file:
            file_contents = file.read()
        
    
        print(file_contents)

        
        return HttpResponse(f"<pre>{file_contents}</pre>")


    return HttpResponse("No blacklist file available.")

#coins & duplicate& valid Number
import re

def validate_phone_number(phone_number):
    
    pattern = re.compile(r'^(\+\d{1,3})?\s?\(?\d{1,4}\)?[\s.-]?\d{3}[\s.-]?\d{4}$')
    return bool(pattern.match(phone_number))

import os
from io import StringIO
def remove_duplicate_and_invalid_contacts(uploaded_file):
    
    unique_valid_contacts = set()
    
   
    file_stream = StringIO(uploaded_file.decode('utf-8'))
    
    for line in file_stream:
        phone_number = line.strip()
        
        
        if validate_phone_number(phone_number):
            unique_valid_contacts.add(phone_number)
        else:
            print(f"Warning: Invalid phone number '{phone_number}' found and skipped.")
    
    # After processing, print the count of unique, valid contacts
    print(len(unique_valid_contacts))
    return len(unique_valid_contacts)



from django.contrib import messages


@login_required
def subtract_coins(request, final_count):
    # Retrieve the current logged-in user
    user = request.user  # No need to use get_object_or_404 because request.user is already the authenticated user

    # Calculate the amount of coins to subtract based on final_count
    final_coins = Decimal(final_count) * Decimal('0.10')

    # Check if the user has enough coins to proceed
    if user.coins >= final_coins:
        # Subtract the coins and save the user object
        user.coins -= final_coins
        user.save()
        
        # Provide feedback to the user about the successful transaction
        messages.success(request, f"Successfully subtracted {final_coins} coins from your account.")
    else:
        # Notify the user that they do not have enough coins
        messages.error(request, "You don't have enough coins to proceed.")