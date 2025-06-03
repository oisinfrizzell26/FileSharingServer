"""
File service layer that integrates FileStorageHandler with Flask app and database
"""
from datetime import datetime, timezone
from Database.models import db, Files
from files import FileStorageHandler, FileStorageConfig

class FileService:
    def __init__(self, app=None):
        self.storage_handler = None
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize with Flask app"""
        config = FileStorageConfig(
            uploads_dir=app.config.get('UPLOADS_DIR', 'uploads'),
            max_file_size=app.config.get('MAX_FILE_SIZE', 100 * 1024 * 1024),
            use_subdirectories=app.config.get('USE_SUBDIRECTORIES', True)
        )
        self.storage_handler = FileStorageHandler(config)
    
    def store_file(self, file_uuid: str, encrypted_data: bytes, owner_id: int):
        """Store file and create database record"""
        # Store file on disk
        file_path, file_size = self.storage_handler.store_encrypted_file(
            file_uuid, encrypted_data
        )
        
        # Create database record
        file_record = Files(
            uuid=file_uuid,
            disk_file_path=file_path,
            owner_id=owner_id,
            created_at=datetime.now(timezone.utc)
        )
        
        db.session.add(file_record)
        db.session.commit()
        
        return file_record
    
    def retrieve_file(self, file_uuid: str) -> bytes:
        """Retrieve file data"""
        # Check database record exists
        file_record = Files.query.filter_by(uuid=file_uuid).first()
        if not file_record:
            raise FileNotFoundError(f"File record not found: {file_uuid}")
        
        # Retrieve from storage
        return self.storage_handler.retrieve_encrypted_file(file_uuid)
    
    def delete_file(self, file_uuid: str):
        """Delete file and database record"""
        # Delete from storage
        self.storage_handler.delete_encrypted_file(file_uuid)
        
        # Delete database record
        Files.query.filter_by(uuid=file_uuid).delete()
        db.session.commit() 