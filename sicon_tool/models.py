from django.db import models
from django.contrib.auth.models import User
import uuid
from django.utils import timezone

class ShareableScan(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_id = models.CharField(max_length=255)
    target = models.CharField(max_length=255)
    scan_type = models.CharField(max_length=50)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_active = models.BooleanField(default=True)
    access_count = models.IntegerField(default=0)
    
    class Meta:
        db_table = 'shareable_scans'
    
    def __str__(self):
        return f"{self.scan_id} by {self.created_by.username}"