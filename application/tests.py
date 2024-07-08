from django.test import TestCase

# Create your tests here.

from django.shortcuts import render, redirect, get_object_or_404
from .form import Student_form
from .models import Student
from datetime import datetime
from django.contrib.auth import login as auth_login
from django.contrib.auth import authenticate
from django.contrib.auth import logout as auth_logout
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
import os
from django.core.paginator import Paginator
from django.conf import settings
import pandas as pd
from datetime import datetime
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
import json


def index(request):
    if request.method == 'POST':
        reg_no = request.POST.get('reg_no')
        data = Student.objects.filter(reg_no=reg_no)
        if data:
            reg_value = get_object_or_404(Student, reg_no=reg_no)
            print(reg_value)
            return render(request, 'update.html',{"reg_value":reg_value})
        return render(request, 'add.html',{"reg_no":reg_no})
    return render(request, 'index.html')


def insert_grade(request):
    if request.method == 'POST':
        reg_no = request.POST.get('reg_no')

        form = Student_form(request.POST)

        if form.is_valid():
            semester1 = float(form.cleaned_data.get('semesterester1')) if form.cleaned_data.get('semesterester1') is not None else None
            semester2 = float(form.cleaned_data.get('semesterester2')) if form.cleaned_data.get('semesterester2') is not None else None
            semester3 = float(form.cleaned_data.get('semesterester3')) if form.cleaned_data.get('semesterester3') is not None else None
            semester4 = float(form.cleaned_data.get('semesterester4')) if form.cleaned_data.get('semesterester4') is not None else None
            semester5 = float(form.cleaned_data.get('semesterester5')) if form.cleaned_data.get('semesterester5') is not None else None
            semester6 = float(form.cleaned_data.get('semesterester6')) if form.cleaned_data.get('semesterester6') is not None else None
            semester7 = float(form.cleaned_data.get('semesterester7')) if form.cleaned_data.get('semesterester7') is not None else None
            semester8 = float(form.cleaned_data.get('semesterester8')) if form.cleaned_data.get('semesterester8') is not None else None

            # Calculate CGPA based on available semesteresters
            if semester8 is not None:
                cgpa = (semester1 + semester2 + semester3 + semester4 + semester5 + semester6 + semester7 + semester8) / 8
            elif semester7 is not None:
                cgpa = (semester1 + semester2 + semester3 + semester4 + semester5 + semester6 + semester7) / 7
            elif semester6 is not None:
                cgpa = (semester1 + semester2 + semester3 + semester4 + semester5 + semester6) / 6
            elif semester5 is not None:
                cgpa = (semester1 + semester2 + semester3 + semester4 + semester5) / 5
            elif semester4 is not None:
                cgpa = (semester1 + semester2 + semester3 + semester4) / 4
            elif semester3 is not None:
                cgpa = (semester1 + semester2 + semester3) / 3
            elif semester2 is not None:
                cgpa = (semester1 + semester2) / 2
            elif semester1 is not None:
                cgpa = semester1

            # Save the form data to the student object
            user = form.save(commit=False)
            user.cgpa = cgpa
            user.semester1 = semester1
            user.semester2 = semester2
            user.semester3 = semester3
            user.semester4 = semester4
            user.semester5 = semester5
            user.semester6 = semester6
            user.semester7 = semester7
            user.semester8 = semester8
            user.save()

            return redirect('index')

        else:
            print('Form errors:', form.errors)  # Debug print for form errors
            return render(request, 'error.html', {'form': form})

    return render(request, 'add.html')


def update_grade(request):
    if request.method == 'POST':
        reg_no = request.POST.get('reg_no')
        try:
            student = Student.objects.get(reg_no=reg_no)
            form = Student_form(request.POST, instance=student)  # Load existing student data into the form
        except Student.DoesNotExist:
            form = Student_form(request.POST)

        if form.is_valid():
            semester1 = float(request.POST.get('semester1'))if request.POST.get('semester1') is not None else None
            semester2 = float(request.POST.get('semester2'))if request.POST.get('semester2') is not None else None
            semester3 = float(request.POST.get('semester3'))if request.POST.get('semester3') is not None else None
            semester4 = float(request.POST.get('semester4'))if request.POST.get('semester4') is not None else None
            semester5 = float(request.POST.get('semester5'))if request.POST.get('semester5') is not None else None
            semester6 = float(request.POST.get('semester6'))if request.POST.get('semester6') is not None else None
            semester7 = float(request.POST.get('semester7'))if request.POST.get('semester7') is not None else None
            semester8 = float(request.POST.get('semester8'))if request.POST.get('semester8') is not None else None
            reg_no = request.POST.get('reg_no')
            batch = request.POST.get('batch')
            student_name = request.POST.get('student_name')
            department = request.POST.get('department')
            sslc = request.POST.get('sslc')
            hsc = request.POST.get('hsc')
            bag_of_log = request.POST.get('bag_of_log')
            no_of_arrear = request.POST.get('no_of_arrear')

            # Calculate CGPA based on available semesteresters
            if semester8 !=0:
                cgpa = (semester1 + semester2 + semester3 + semester4 + semester5 + semester6 + semester7 + semester8) / 8
            elif semester7 !=0:
                cgpa = (semester1 + semester2 + semester3 + semester4 + semester5 + semester6 + semester7) / 7
            elif semester6 !=0:
                cgpa = (semester1 + semester2 + semester3 + semester4 + semester5 + semester6) / 6
            elif semester5 !=0:
                cgpa = (semester1 + semester2 + semester3 + semester4 + semester5) / 5
            elif semester4 !=0:
                cgpa = (semester1 + semester2 + semester3 + semester4) / 4
            elif semester3 !=0:
                cgpa = (semester1 + semester2 + semester3) / 3
            elif semester2 !=0:
                cgpa = (semester1 + semester2) / 2
            elif semester1 !=0:
                cgpa = semester1
            data = get_object_or_404(Student, reg_no=reg_no)
            data.cgpa = cgpa
            data.semester1 = semester1
            data.semester2 = semester2
            data.semester3 = semester3
            data.semester4 = semester4
            data.semester5 = semester5
            data.semester6 = semester6
            data.semester7 = semester7
            data.semester8 = semester8
            data.batch = batch
            data.student_name = student_name
            data.department = department
            data.sslc = sslc
            data.hsc = hsc
            data.bag_of_log = bag_of_log
            data.no_of_arrear = no_of_arrear

            data.save()

            return redirect('index')

        else:
            print('Form errors:', form.errors)  # Debug print for form errors
            return render(request, 'error.html', {'form': form})

    return render(request, 'add.html')

def dashboard(request):
    user = request.session.get('email')
    data = Student.objects.all()

    if request.method == 'POST':
        cgpa = request.POST.get('cgpa')
        no_of_arrear = request.POST.get('no_of_arrear')
        bag_of_log = request.POST.getlist('bag_of_log')
        batch = request.POST.get('batch')

        # Initialize filters
        filters = {}

        if cgpa:
            filters['cgpa__gte'] = float(cgpa)
        if no_of_arrear:
            filters['no_of_arrear__lte'] = int(no_of_arrear)
        if batch:
            filters['batch'] = batch

        # Apply filters to the queryset
        data = Student.objects.filter(**filters)

        print("-----------------------", cgpa, no_of_arrear, bag_of_log, batch)
        print(data)
        return render(request, 'hod/dashboard.html', {'data': data})
    
    return render(request, 'hod/dashboard.html', )
