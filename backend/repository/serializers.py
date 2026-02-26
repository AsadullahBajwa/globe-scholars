from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import ScholarlyWork, Reaction

User = get_user_model()


class UploaderSerializer(serializers.ModelSerializer):
    """Nested serializer for uploader info"""
    full_name = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = ['id', 'username', 'full_name', 'affiliation']
    
    def get_full_name(self, obj):
        return obj.get_full_name()


class ScholarlyWorkListSerializer(serializers.ModelSerializer):
    """For list view — lightweight"""
    uploader = UploaderSerializer(read_only=True)
    reaction_count = serializers.SerializerMethodField()
    user_has_reacted = serializers.SerializerMethodField()
    
    class Meta:
        model = ScholarlyWork
        fields = [
            'id', 'title', 'authors', 'publication_year',
            'file_type', 'file_size', 'uploaded_at',
            'uploader', 'reaction_count', 'user_has_reacted',
            'conversion_status'
        ]
    
    def get_reaction_count(self, obj):
        return obj.reactions.count()
    
    def get_user_has_reacted(self, obj):
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return obj.reactions.filter(user=request.user).exists()
        return False


class ScholarlyWorkDetailSerializer(serializers.ModelSerializer):
    """For detail view — full info"""
    uploader = UploaderSerializer(read_only=True)
    reaction_count = serializers.SerializerMethodField()
    user_has_reacted = serializers.SerializerMethodField()
    author_list = serializers.SerializerMethodField()
    download_url = serializers.SerializerMethodField()
    
    class Meta:
        model = ScholarlyWork
        fields = [
            'id', 'title', 'authors', 'author_list', 'publication_year',
            'description', 'keywords', 'file_type', 'file_size',
            'original_filename', 'uploader', 'uploaded_at', 'updated_at',
            'reaction_count', 'user_has_reacted', 'download_url',
            'conversion_status', 'conversion_progress'
        ]
    
    def get_reaction_count(self, obj):
        return obj.reactions.count()
    
    def get_user_has_reacted(self, obj):
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return obj.reactions.filter(user=request.user).exists()
        return False
    
    def get_author_list(self, obj):
        return obj.get_author_list()
    
    def get_download_url(self, obj):
        request = self.context.get('request')
        if request:
            return request.build_absolute_uri(f'/api/repository/{obj.id}/download/')
        return None


class ScholarlyWorkUploadSerializer(serializers.ModelSerializer):
    """For file upload (RM22)"""
    file = serializers.FileField()
    
    class Meta:
        model = ScholarlyWork
        fields = [
            'title', 'authors', 'publication_year',
            'description', 'keywords', 'file'
        ]
    
    def validate_file(self, file):
        # Validate file type (RM13)
        allowed_types = ['application/pdf', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']
        if file.content_type not in allowed_types:
            raise serializers.ValidationError("Only PDF and DOCX files are allowed.")
        
        # Validate file size (RM19)
        max_size = 20 * 1024 * 1024  # 20 MB
        if file.size > max_size:
            raise serializers.ValidationError("File size cannot exceed 20 MB.")
        
        return file
    
    def create(self, validated_data):
        file = validated_data['file']
        
        # Determine file type
        file_type = 'pdf' if file.content_type == 'application/pdf' else 'docx'
        
        # Set conversion status
        conversion_status = 'completed' if file_type == 'pdf' else 'pending'
        
        scholarly_work = ScholarlyWork.objects.create(
            title=validated_data['title'],
            authors=validated_data['authors'],
            publication_year=validated_data['publication_year'],
            description=validated_data.get('description', ''),
            keywords=validated_data.get('keywords', ''),
            file=file,
            original_filename=file.name,
            file_size=file.size,
            file_type=file_type,
            conversion_status=conversion_status,
            uploader=self.context['request'].user
        )
        
        # Trigger DOCX conversion if needed (RM14) - we'll implement this later
        # if file_type == 'docx':
        #     from .tasks import convert_docx_to_pdf
        #     convert_docx_to_pdf.delay(scholarly_work.id)
        
        return scholarly_work


class ReactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Reaction
        fields = ['id', 'user', 'scholarly_work', 'created_at']
        read_only_fields = ['user']