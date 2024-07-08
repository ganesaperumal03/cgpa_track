import random
from faker import Faker
from django.http import HttpResponse
from application.models import Student

faker = Faker()

def populate_fake_data(request):
    print('Populating Personal_Details with fake data...')

    for _ in range(200):
        Student.objects.create(
            reg_no=faker.unique.random_number(digits=13),
            batch=faker.random_element(elements=('2021-25','2021-25')),
            student_name=faker.name(),
            department=faker.word(),
            cgpa=round(faker.random.uniform(4.0, 9.0), 2),
            sslc=round(faker.random.uniform(50.0, 100.0), 2),
            hsc=round(faker.random.uniform(50.0, 100.0), 2),
            bag_of_log=faker.random_element(elements=('Yes', 'No')),
            no_of_arrear=faker.random_int(min=0, max=5),
            semester1=round(faker.random.uniform(4.0, 9.0), 2) if faker.boolean() else None,
            semester2=round(faker.random.uniform(4.0, 9.0), 2) if faker.boolean() else None,
            semester3=round(faker.random.uniform(4.0, 9.0), 2) if faker.boolean() else None,
            semester4=round(faker.random.uniform(4.0, 9.0), 2) if faker.boolean() else None,
            semester5=round(faker.random.uniform(4.0, 9.0), 2) if faker.boolean() else None,
            semester6=round(faker.random.uniform(4.0, 9.0), 2) if faker.boolean() else None,
            semester7=round(faker.random.uniform(4.0, 9.0), 2) if faker.boolean() else None,
            semester8=round(faker.random.uniform(4.0, 9.0), 2) if faker.boolean() else None,
        )

    return HttpResponse('Populated 200 student records with fake data.')
