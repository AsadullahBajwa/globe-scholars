from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display  = ['email', 'username', 'first_name', 'last_name', 'is_staff', 'created_at']
    list_filter   = ['is_staff', 'is_active']
    search_fields = ['email', 'username', 'first_name', 'last_name']
    ordering      = ['-created_at']

    fieldsets = (
        (None,           {'fields': ('email', 'username', 'password')}),
        ('Personal Info',{'fields': ('first_name', 'last_name', 'bio', 'affiliation', 'country', 'website')}),
        ('Permissions',  {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login',)}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'password1', 'password2'),
        }),
    )