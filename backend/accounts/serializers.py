from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password

User = get_user_model()


class SignupSerializer(serializers.ModelSerializer):
    password  = serializers.CharField(write_only=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, label="Confirm Password")

    class Meta:
        model  = User
        fields = [
            'email', 'username', 'first_name', 'last_name',
            'bio', 'affiliation', 'country', 'website',
            'password', 'password2'
        ]
        extra_kwargs = {
            'email': {'required': False, 'allow_blank': True},  # ← Add this line
        }

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Passwords do not match."})
        return attrs

    def create(self, validated_data):
        validated_data.pop('password2')
        user = User.objects.create_user(**validated_data)
        return user


class LoginSerializer(serializers.Serializer):
    username    = serializers.CharField()
    password = serializers.CharField(write_only=True)


class UserProfileSerializer(serializers.ModelSerializer):
    full_name      = serializers.SerializerMethodField()
    upload_count   = serializers.SerializerMethodField()
    total_reactions = serializers.SerializerMethodField()

    class Meta:
        model  = User
        fields = [
            'id', 'email', 'username', 'first_name', 'last_name',
            'full_name', 'bio', 'affiliation', 'country', 'website',
            'created_at', 'upload_count', 'total_reactions'
        ]
        read_only_fields = ['id', 'email', 'created_at']

    def get_full_name(self, obj):
        return obj.get_full_name()

    def get_upload_count(self, obj):
        return obj.uploaded_files.count() if hasattr(obj, 'uploaded_files') else 0

    def get_total_reactions(self, obj):
        if hasattr(obj, 'uploaded_files'):
            return sum(f.reactions.count() for f in obj.uploaded_files.all())
        return 0


class PublicUserProfileSerializer(serializers.ModelSerializer):
    """For guest users — no email exposed"""
    full_name    = serializers.SerializerMethodField()
    upload_count = serializers.SerializerMethodField()

    class Meta:
        model  = User
        fields = [
            'id', 'username', 'first_name', 'last_name', 'full_name',
            'bio', 'affiliation', 'country', 'website',
            'created_at', 'upload_count'
        ]

    def get_full_name(self, obj):
        return obj.get_full_name()

    def get_upload_count(self, obj):
        return obj.uploaded_files.count() if hasattr(obj, 'uploaded_files') else 0


class UpdateProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model  = User
        fields = [
            'username', 'first_name', 'last_name',
            'bio', 'affiliation', 'country', 'website'
        ]

class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()