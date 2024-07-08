from django.db import models

# Create your models here.
class Student(models.Model):
    reg_no = models.CharField(max_length=20, primary_key=True)
    batch = models.CharField(max_length=100)
    student_name = models.CharField(max_length=100)
    department = models.CharField(max_length=100)
    cgpa = models.FloatField()
    sslc = models.FloatField()
    hsc = models.FloatField()
    bag_of_log = models.TextField(blank=True, null=True)
    no_of_arrear = models.IntegerField()
    
    # Semester fields as FloatField to represent GPA or similar values
    semester1 = models.CharField(max_length=20,blank=True, null=True)
    semester2 = models.CharField(max_length=20,blank=True, null=True)
    semester3 = models.CharField(max_length=20,blank=True, null=True)
    semester4 = models.CharField(max_length=20,blank=True, null=True)
    semester5 = models.CharField(max_length=20,blank=True, null=True)
    semester6 = models.CharField(max_length=20,blank=True, null=True)
    semester7 = models.CharField(max_length=20,blank=True, null=True)
    semester8 = models.CharField(max_length=20,blank=True, null=True)


class User(models.Model):
    Name = models.CharField(max_length=100)
    user_name = models.CharField(max_length=100)
    Department = models.CharField(max_length=100)
    email = models.CharField(max_length=100)
    Password = models.CharField(max_length=100)
    conform_Password = models.CharField(max_length=100)