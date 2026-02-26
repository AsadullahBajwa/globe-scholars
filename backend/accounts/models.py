from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models


class UserManager(BaseUserManager):

    def create_user(self,  username, email=None, password=None, **extra_fields):
        if not username:
            raise ValueError("Username is required")
        
        if email:  # ← Only normalize if email is provided
            email = self.normalize_email(email)
        
        user = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username,  email=None, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(username, email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    email        = models.EmailField(unique=True, blank=True, null=True)
    username     = models.CharField(max_length=50, unique=True)
    first_name   = models.CharField(max_length=50, blank=True)
    last_name    = models.CharField(max_length=50, blank=True)
    bio          = models.TextField(blank=True)
    affiliation  = models.CharField(max_length=200, blank=True)  # university/institution
    country      = models.CharField(max_length=100, blank=True)
    website      = models.URLField(blank=True)
    is_active    = models.BooleanField(default=True)
    is_staff     = models.BooleanField(default=False)
    created_at   = models.DateTimeField(auto_now_add=True)
    updated_at   = models.DateTimeField(auto_now=True)

    objects = UserManager()

    USERNAME_FIELD  = 'username'
    REQUIRED_FIELDS = ['email']

    def __str__(self):
        return self.username

    def get_full_name(self):
        return f"{self.first_name} {self.last_name}".strip() or self.username