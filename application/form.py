from django import forms
from .models import Student,User


class Student_form(forms.ModelForm):
    class Meta:
        model = Student
        fields = '__all__'
        exclude = ["cgpa"]


class userform(forms.ModelForm):
    class Meta:
        model = User
        fields = [
            'Name', 'user_name',  'Department', 'email',
            'Password', 'conform_Password'
 ]
