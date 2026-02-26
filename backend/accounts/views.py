from rest_framework import status, generics, filters
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate, get_user_model
from django.http import HttpResponse
from io import BytesIO
import weasyprint
from drf_spectacular.utils import extend_schema, OpenApiParameter

from .serializers import (
    SignupSerializer,
    LoginSerializer,
    UserProfileSerializer,
    PublicUserProfileSerializer,
    UpdateProfileSerializer,
    LogoutSerializer,
)

User = get_user_model()


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access':  str(refresh.access_token),
    }


class SignupView(APIView):
    permission_classes = [AllowAny]

    @extend_schema(
        request=SignupSerializer,
        responses={201: UserProfileSerializer},
        description="Register a new user account"
    )
    def post(self, request):
        serializer = SignupSerializer(data=request.data)
        if serializer.is_valid():
            user   = serializer.save()
            tokens = get_tokens_for_user(user)
            return Response({
                'message': 'Account created successfully.',
                'user':    UserProfileSerializer(user).data,
                'tokens':  tokens,
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    permission_classes = [AllowAny]

    @extend_schema(
        request=LoginSerializer,
        responses={200: UserProfileSerializer},
        description="Login with email and password"
    )
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        username    = serializer.validated_data['username']
        password = serializer.validated_data['password']
        user     = authenticate(request, username=username, password=password)

        if user is None:
            return Response(
                {'error': 'Invalid username or password.'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        if not user.is_active:
            return Response(
                {'error': 'Account is disabled.'},
                status=status.HTTP_403_FORBIDDEN
            )

        tokens = get_tokens_for_user(user)
        return Response({
            'message': 'Login successful.',
            'user':    UserProfileSerializer(user).data,
            'tokens':  tokens,
        }, status=status.HTTP_200_OK)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        request=LogoutSerializer,
        responses={200: {'message': 'string'}},
        description="Logout and blacklist refresh token"
    )
    def post(self, request):
        try:
            refresh_token = request.data.get('refresh')
            if not refresh_token:
                return Response(
                    {'error': 'Refresh token is required.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            token = RefreshToken(refresh_token)
            token.blacklist()
            
            return Response(
                {'message': 'Logged out successfully.'},
                status=status.HTTP_200_OK
            )
        except Exception as e:
            return Response(
                {'error': f'Token error: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )

class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        responses={200: UserProfileSerializer},
        description="Get current user profile"
    )
    def get(self, request):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data)

    @extend_schema(
        request=UpdateProfileSerializer,
        responses={200: UserProfileSerializer},
        description="Update current user profile"
    )
    def patch(self, request):
        serializer = UpdateProfileSerializer(
            request.user,
            data=request.data,
            partial=True
        )
        if serializer.is_valid():
            serializer.save()
            return Response({
                'message': 'Profile updated successfully.',
                'user':    UserProfileSerializer(request.user).data,
            })
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ScholarListView(generics.ListAPIView):
    """Global scholar overview — all users, public access (RM11)"""
    permission_classes = [AllowAny]
    serializer_class   = PublicUserProfileSerializer
    filter_backends    = [filters.SearchFilter, filters.OrderingFilter]
    search_fields      = ['username', 'first_name', 'last_name', 'affiliation', 'country']
    ordering_fields    = ['username', 'created_at']
    ordering           = ['-created_at']

    def get_queryset(self):
        return User.objects.filter(is_active=True, is_staff=False)


class ScholarDetailView(generics.RetrieveAPIView):
    """Public profile view for any scholar (RM5)"""
    permission_classes = [AllowAny]
    serializer_class   = PublicUserProfileSerializer
    queryset           = User.objects.filter(is_active=True)


class ProfileExportView(APIView):
    """Download profile as PDF — CV-like format (RM12)"""
    permission_classes = [AllowAny]

    @extend_schema(
        responses={200: bytes},
        description="Export user profile as PDF"
    )
    def get(self, request, pk):
        try:
            user = User.objects.get(pk=pk, is_active=True)
        except User.DoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

        html_content = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; color: #333; }}
                h1   {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
                h2   {{ color: #3498db; margin-top: 25px; }}
                p    {{ line-height: 1.6; }}
                .label {{ font-weight: bold; }}
            </style>
        </head>
        <body>
            <h1>{user.get_full_name() or user.username}</h1>
            <p><span class="label">Email:</span> {user.email}</p>
            <p><span class="label">Username:</span> {user.username}</p>
            {'<p><span class="label">Affiliation:</span> ' + user.affiliation + '</p>' if user.affiliation else ''}
            {'<p><span class="label">Country:</span> ' + user.country + '</p>' if user.country else ''}
            {'<p><span class="label">Website:</span> ' + user.website + '</p>' if user.website else ''}
            {'<h2>About</h2><p>' + user.bio + '</p>' if user.bio else ''}
            <h2>Scholar Since</h2>
            <p>{user.created_at.strftime('%B %Y')}</p>
            <h2>Uploaded Works</h2>
            <p>{user.uploaded_files.count() if hasattr(user, 'uploaded_files') else 0} scholarly works uploaded</p>
        </body>
        </html>
        """

        pdf_file = BytesIO()
        weasyprint.HTML(string=html_content).write_pdf(pdf_file)
        pdf_file.seek(0)

        response = HttpResponse(pdf_file, content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="{user.username}_profile.pdf"'
        return response