# Generated by Django 2.2 on 2021-01-04 14:17

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0002_auto_20210104_1417'),
    ]

    operations = [
        migrations.AlterField(
            model_name='transaction',
            name='transaction_id',
            field=models.UUIDField(default=uuid.UUID('76bdf7ad-608a-4c91-98ad-1b86f3062730')),
        ),
    ]