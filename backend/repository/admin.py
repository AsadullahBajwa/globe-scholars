from django.contrib import admin
from .models import ScholarlyWork, Reaction


@admin.register(ScholarlyWork)
class ScholarlyWorkAdmin(admin.ModelAdmin):
    list_display = ['title', 'authors', 'publication_year', 'uploader', 'file_type', 'conversion_status', 'uploaded_at']
    list_filter = ['file_type', 'conversion_status', 'publication_year']
    search_fields = ['title', 'authors', 'keywords']
    readonly_fields = ['uploaded_at', 'updated_at', 'file_size', 'original_filename']


@admin.register(Reaction)
class ReactionAdmin(admin.ModelAdmin):
    list_display = ['user', 'scholarly_work', 'created_at']
    list_filter = ['created_at']