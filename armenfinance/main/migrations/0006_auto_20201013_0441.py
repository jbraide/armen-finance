# Generated by Django 2.2 on 2020-10-13 04:41

from django.conf import settings
import django.core.validators
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0005_auto_20201002_0911'),
    ]

    operations = [
        migrations.AlterField(
            model_name='transaction',
            name='transaction_id',
            field=models.UUIDField(default=uuid.UUID('0e0180b8-9d57-4f82-aee6-ba21c73476be')),
        ),
        migrations.CreateModel(
            name='AccountDetails',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('account_number', models.PositiveIntegerField(validators=[django.core.validators.MaxValueValidator(11)])),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]