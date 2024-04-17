# 工具包
from faker import Faker
from faker.providers import date_time, company, automotive

fake = Faker("zh_CN")
fake.add_provider(date_time)
fake.add_provider(company)
fake.add_provider(automotive)
