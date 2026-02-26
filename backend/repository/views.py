from rest_framework import status, generics, filters
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.parsers import MultiPartParser, FormParser
from django.http import FileResponse, Http404
from django.shortcuts import get_object_or_404
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema, OpenApiParameter

from .models import ScholarlyWork, Reaction
from .serializers import (
    ScholarlyWorkListSerializer,
    ScholarlyWorkDetailSerializer,
    ScholarlyWorkUploadSerializer,
    ReactionSerializer,
)


class ScholarlyWorkUploadView(APIView):
    """Upload scholarly work file (RM4, RM13, RM19, RM22)"""
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    @extend_schema(
        request=ScholarlyWorkUploadSerializer,
        responses={201: ScholarlyWorkDetailSerializer},
        description="Upload a scholarly work (PDF or DOCX, max 20MB)"
    )
    def post(self, request):
        serializer = ScholarlyWorkUploadSerializer(
            data=request.data,
            context={'request': request}
        )
        
        if serializer.is_valid():
            scholarly_work = serializer.save()
            response_serializer = ScholarlyWorkDetailSerializer(
                scholarly_work,
                context={'request': request}
            )
            return Response(
                response_serializer.data,
                status=status.HTTP_201_CREATED
            )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ScholarlyWorkListView(generics.ListAPIView):
    """List all scholarly works with search and filters (RM7, RM8, RM9, RS1, RS2, RS6)"""
    permission_classes = [AllowAny]
    serializer_class = ScholarlyWorkListSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['publication_year', 'file_type']
    search_fields = ['title', 'authors', 'keywords']
    ordering_fields = ['uploaded_at', 'title', 'publication_year']
    ordering = ['-uploaded_at']  # Default sort by newest (RS6)

    def get_queryset(self):
        queryset = ScholarlyWork.objects.all()
        
        # Filter by author name (RS1)
        author = self.request.query_params.get('author', None)
        if author:
            queryset = queryset.filter(authors__icontains=author)
        
        return queryset


class ScholarlyWorkDetailView(generics.RetrieveAPIView):
    """Get details of a specific scholarly work"""
    permission_classes = [AllowAny]
    serializer_class = ScholarlyWorkDetailSerializer
    queryset = ScholarlyWork.objects.all()


class ScholarlyWorkDownloadView(APIView):
    """Download file - requires authentication (RM6)"""
    permission_classes = [IsAuthenticated]

    @extend_schema(
        responses={200: bytes},
        description="Download scholarly work file (authenticated users only)"
    )
    def get(self, request, pk):
        scholarly_work = get_object_or_404(ScholarlyWork, pk=pk)
        
        # Serve converted PDF if available, otherwise original
        if scholarly_work.file_type == 'docx' and scholarly_work.converted_pdf:
            file_to_serve = scholarly_work.converted_pdf
            filename = f"{scholarly_work.original_filename.rsplit('.', 1)[0]}.pdf"
        else:
            file_to_serve = scholarly_work.file
            filename = scholarly_work.original_filename
        
        try:
            response = FileResponse(
                file_to_serve.open('rb'),
                as_attachment=True,
                filename=filename
            )
            return response
        except FileNotFoundError:
            raise Http404("File not found.")


class ScholarlyWorkDeleteView(APIView):
    """Delete own uploaded file (RM16)"""
    permission_classes = [IsAuthenticated]

    @extend_schema(
        responses={204: None},
        description="Delete your own scholarly work"
    )
    def delete(self, request, pk):
        scholarly_work = get_object_or_404(ScholarlyWork, pk=pk)
        
        # Check ownership
        if scholarly_work.uploader != request.user:
            return Response(
                {'error': 'You can only delete your own files.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Delete files from filesystem
        if scholarly_work.file:
            scholarly_work.file.delete(save=False)
        if scholarly_work.converted_pdf:
            scholarly_work.converted_pdf.delete(save=False)
        
        # Delete database record (cascades to reactions)
        scholarly_work.delete()
        
        return Response(
            {'message': 'Scholarly work deleted successfully.'},
            status=status.HTTP_204_NO_CONTENT
        )


class ReactToWorkView(APIView):
    """Toggle reaction (like) on scholarly work (RS4)"""
    permission_classes = [IsAuthenticated]

    @extend_schema(
        responses={200: {'reaction_count': 'integer', 'message': 'string'}},
        description="Toggle like/reaction on scholarly work"
    )
    def post(self, request, pk):
        scholarly_work = get_object_or_404(ScholarlyWork, pk=pk)
        
        # Check if user already reacted
        reaction = Reaction.objects.filter(
            user=request.user,
            scholarly_work=scholarly_work
        ).first()
        
        if reaction:
            # Remove reaction (unlike)
            reaction.delete()
            message = 'Reaction removed'
        else:
            # Add reaction (like)
            Reaction.objects.create(
                user=request.user,
                scholarly_work=scholarly_work
            )
            message = 'Reaction added'
        
        return Response({
            'message': message,
            'reaction_count': scholarly_work.reactions.count()
        })


class ConversionStatusView(APIView):
    """Check DOCX to PDF conversion status (RM15)"""
    permission_classes = [IsAuthenticated]

    @extend_schema(
        responses={200: ScholarlyWorkDetailSerializer},
        description="Get conversion status for uploaded DOCX file"
    )
    def get(self, request, pk):
        scholarly_work = get_object_or_404(ScholarlyWork, pk=pk)
        serializer = ScholarlyWorkDetailSerializer(
            scholarly_work,
            context={'request': request}
        )
        return Response(serializer.data)