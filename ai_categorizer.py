"""
AI-powered file categorization and tagging system
"""
import os
import mimetypes
from pathlib import Path
import json

# Simple rule-based categorization (can be enhanced with ML models)
CATEGORY_MAPPING = {
    'image': ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml', 'image/bmp'],
    'video': ['video/mp4', 'video/avi', 'video/mov', 'video/wmv', 'video/flv', 'video/webm'],
    'audio': ['audio/mp3', 'audio/wav', 'audio/flac', 'audio/aac', 'audio/ogg'],
    'document': ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                'application/vnd.ms-powerpoint', 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
                'text/plain', 'text/rtf'],
    'archive': ['application/zip', 'application/x-rar-compressed', 'application/x-7z-compressed',
               'application/x-tar', 'application/gzip'],
    'code': ['text/x-python', 'text/x-java-source', 'text/x-c', 'text/x-c++', 'text/javascript',
            'text/css', 'text/html', 'application/json', 'text/xml']
}

FILE_EXTENSION_TAGS = {
    '.pdf': ['document', 'portable', 'text'],
    '.docx': ['document', 'word', 'text', 'office'],
    '.xlsx': ['spreadsheet', 'excel', 'data', 'office'],
    '.pptx': ['presentation', 'powerpoint', 'slides', 'office'],
    '.jpg': ['image', 'photo', 'jpeg'],
    '.jpeg': ['image', 'photo', 'jpeg'],
    '.png': ['image', 'graphic', 'transparent'],
    '.gif': ['image', 'animated', 'graphic'],
    '.mp4': ['video', 'movie', 'media'],
    '.avi': ['video', 'movie', 'media'],
    '.mp3': ['audio', 'music', 'sound'],
    '.wav': ['audio', 'sound', 'uncompressed'],
    '.zip': ['archive', 'compressed', 'bundle'],
    '.py': ['code', 'python', 'script'],
    '.js': ['code', 'javascript', 'web'],
    '.html': ['code', 'web', 'markup'],
    '.css': ['code', 'style', 'web'],
    '.txt': ['text', 'plain', 'document'],
    '.json': ['data', 'json', 'structured'],
    '.xml': ['data', 'markup', 'structured']
}

def categorize_file(filename, mime_type=None):
    """
    Categorize a file based on its name and MIME type
    """
    if not mime_type:
        mime_type, _ = mimetypes.guess_type(filename)
    
    if not mime_type:
        return 'other'
    
    # Check each category
    for category, mime_types in CATEGORY_MAPPING.items():
        if mime_type in mime_types:
            return category
    
    # Fallback to extension-based categorization
    ext = Path(filename).suffix.lower()
    if ext in ['.py', '.js', '.html', '.css', '.json', '.xml', '.java', '.cpp', '.c']:
        return 'code'
    elif ext in ['.txt', '.md', '.rtf']:
        return 'document'
    
    return 'other'

def generate_tags(filename, mime_type=None):
    """
    Generate tags for a file based on its properties
    """
    tags = set()
    
    # Get extension-based tags
    ext = Path(filename).suffix.lower()
    if ext in FILE_EXTENSION_TAGS:
        tags.update(FILE_EXTENSION_TAGS[ext])
    
    # Add filename-based tags (simple keyword extraction)
    name_parts = Path(filename).stem.lower().replace('_', ' ').replace('-', ' ').split()
    for part in name_parts:
        if len(part) > 2:  # Only add meaningful words
            tags.add(part)
    
    # Add MIME type based tags
    if mime_type:
        main_type = mime_type.split('/')[0]
        tags.add(main_type)
        
        if 'office' in mime_type or 'openxml' in mime_type:
            tags.add('office')
        if 'microsoft' in mime_type:
            tags.add('microsoft')
    
    # Add size-based tags (would need file size parameter)
    # This is a placeholder for more advanced tagging
    
    return list(tags)

def extract_text_content(file_path, mime_type):
    """
    Extract text content from files for advanced analysis
    This is a placeholder for more sophisticated text extraction
    """
    try:
        if mime_type == 'text/plain':
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()[:1000]  # First 1000 chars
        elif mime_type == 'application/pdf':
            # Would use PyPDF2 or similar
            return "PDF content extraction not implemented"
        # Add more extractors as needed
    except:
        pass
    return ""

def analyze_content_sentiment(text_content):
    """
    Analyze sentiment of text content
    Placeholder for sentiment analysis
    """
    # This would use a proper sentiment analysis library
    positive_words = ['good', 'great', 'excellent', 'amazing', 'wonderful']
    negative_words = ['bad', 'terrible', 'awful', 'horrible', 'worst']
    
    text_lower = text_content.lower()
    pos_count = sum(1 for word in positive_words if word in text_lower)
    neg_count = sum(1 for word in negative_words if word in text_lower)
    
    if pos_count > neg_count:
        return 'positive'
    elif neg_count > pos_count:
        return 'negative'
    else:
        return 'neutral'

def get_file_insights(filename, mime_type, file_size=None):
    """
    Get comprehensive insights about a file
    """
    category = categorize_file(filename, mime_type)
    tags = generate_tags(filename, mime_type)
    
    insights = {
        'category': category,
        'tags': tags,
        'mime_type': mime_type,
        'is_media': category in ['image', 'video', 'audio'],
        'is_document': category == 'document',
        'is_code': category == 'code',
        'estimated_processing_time': estimate_processing_time(file_size, category)
    }
    
    return insights

def estimate_processing_time(file_size, category):
    """
    Estimate processing time based on file size and type
    """
    if not file_size:
        return 'unknown'
    
    # Simple estimation in seconds
    base_time = {
        'image': 0.1,
        'document': 0.5,
        'video': 2.0,
        'audio': 1.0,
        'code': 0.1,
        'archive': 1.5,
        'other': 0.5
    }
    
    mb_size = file_size / (1024 * 1024)
    estimated_seconds = base_time.get(category, 0.5) * mb_size
    
    if estimated_seconds < 1:
        return 'instant'
    elif estimated_seconds < 10:
        return 'fast'
    elif estimated_seconds < 60:
        return 'moderate'
    else:
        return 'slow'
