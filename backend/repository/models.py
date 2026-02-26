from django.db import models
from django.conf import settings
from django.core.validators import FileExtensionValidator


def scholarly_work_upload_path(instance, filename):
    """Generate upload path: media/scholarly_works/user_id/filename"""
    return f'scholarly_works/{instance.uploader.id}/{filename}'


class ScholarlyWork(models.Model):
    # Required fields (RM22)
    title           = models.CharField(max_length=500)
    authors         = models.CharField(max_length=500, help_text="Comma-separated author names")
    publication_year = models.IntegerField()
    
    # File handling
    file            = models.FileField(
        upload_to=scholarly_work_upload_path,
        validators=[FileExtensionValidator(allowed_extensions=['pdf', 'docx'])]
    )
    original_filename = models.CharField(max_length=255)
    file_size       = models.BigIntegerField(help_text="File size in bytes")
    file_type       = models.CharField(max_length=50)  # 'pdf' or 'docx'
    
    # DOCX conversion tracking (RM14, RM15)
    converted_pdf   = models.FileField(upload_to='converted_pdfs/', blank=True, null=True)
    conversion_status = models.CharField(
        max_length=20,
        choices=[
            ('pending', 'Pending'),
            ('processing', 'Processing'),
            ('completed', 'Completed'),
            ('failed', 'Failed'),
        ],
        default='completed'  # PDFs don't need conversion
    )
    conversion_progress = models.IntegerField(default=0, help_text="Percentage 0-100")
    
    # Metadata
    uploader        = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='uploaded_files'
    )
    uploaded_at     = models.DateTimeField(auto_now_add=True)
    updated_at      = models.DateTimeField(auto_now=True)
    
    # Additional fields
    description     = models.TextField(blank=True)
    keywords        = models.CharField(max_length=500, blank=True, help_text="Comma-separated keywords")
    
    class Meta:
        ordering = ['-uploaded_at']
        verbose_name = 'Scholarly Work'
        verbose_name_plural = 'Scholarly Works'
    
    def __str__(self):
        return f"{self.title} ({self.publication_year})"
    
    @property
    def file_url(self):
        """Return the file to serve - converted PDF if available, otherwise original"""
        if self.file_type == 'docx' and self.converted_pdf:
            return self.converted_pdf.url
        return self.file.url
    
    def get_author_list(self):
        """Return authors as a list"""
        return [author.strip() for author in self.authors.split(',')]


class Reaction(models.Model):
    """Like/reaction system (RS4)"""
    user            = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='reactions'
    )
    scholarly_work  = models.ForeignKey(
        ScholarlyWork,
        on_delete=models.CASCADE,
        related_name='reactions'
    )
    created_at      = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['user', 'scholarly_work']  # One reaction per user per work
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.user.username} reacted to {self.scholarly_work.title}"