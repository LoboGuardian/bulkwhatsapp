from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.conf import settings
from django.db.models.signals import post_save
from decimal import Decimal

class CustomUserManager(BaseUserManager):
    def create_user(self, email, username, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user 

    def create_superuser(self, email, username, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, username, password, **extra_fields)

class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=150, unique=True)
    coins=models.DecimalField(max_digits=10,decimal_places=2, default=Decimal('0.00'))
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.email
   
    


class Whitelist(models.Model):
   
    email = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    whitelist_phone = models.FileField(upload_to='documents/', blank=True, null=True)

    def __str__(self):
        return f"{self.email}"

class Blacklist(models.Model):
    
    email = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    blacklist_phone = models.FileField(upload_to='documents/', blank=True, null=True)

    def __str__(self):
        return f"{self.email}"
    
class MessageSendInfo(models.Model):
    email = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    message_date = models.DateTimeField()  
    message_delivery = models.IntegerField() 
    message_send = models.IntegerField()  
    message_failed = models.IntegerField()  


    def __str__(self):
        
        return f"{self.email}"
   
        
