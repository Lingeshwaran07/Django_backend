from django.db import models
from django.contrib.auth.models import AbstractUser , BaseUserManager , AbstractBaseUser
from django.utils.translation import gettext_lazy as _
import uuid

class CustomUserManager(BaseUserManager):

    def _create_user(self, username,email, password=None, **extra_fields):
        """Create and save a User with the given username,email,phone no  and password."""
        if not email:
            raise ValueError('the email has to be provided')
        email = self.normalize_email(email)
        user = self.model(email=email,username = username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_user(self, username,email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(username,email, password, **extra_fields)

    def create_superuser(self, username,email, password=None, **extra_fields):
        """Create and save a SuperUser with the given username, phnne no ,email and password."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(username,email, password, **extra_fields)

'''this is my custom user overwridden the default user model offered by django'''

class CustomUser(AbstractUser):
    email = models.CharField(max_length=255, unique=True
        )
    #uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.CharField(

        max_length=150,null=False,


    )


    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    user_manager_obj = CustomUserManager()