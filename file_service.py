"""
File service layer that integrates FileStorageHandler with Flask app and database
"""
from datetime import datetime, timezone
from Database.models import db, Files
from files import FileStorageHandler, FileStorageConfig
from flask import current_app

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
    
    def delete_file(self, file_uuid: str, owner_id_check: int):
        """Delete file from disk and its database record, ensuring ownership."""
        # Find the database record first
        file_record = Files.query.filter_by(uuid=file_uuid).first()

        if not file_record:
            app_logger.info(f"File record with UUID {file_uuid} not found in database for deletion attempt.")
            raise FileNotFoundError(f"File with UUID {file_uuid} not found.") # Raise error to be caught by route

        # Check ownership
        if file_record.owner_id != owner_id_check:
            app_logger.warning(f"User {owner_id_check} attempted to delete file {file_uuid} owned by {file_record.owner_id}.")
            # Do not raise FileNotFoundError here, use a specific permission error or handle in route
            raise PermissionError(f"User does not have permission to delete file {file_uuid}.")

        try:
            # Attempt to delete from disk storage first
            # FileStorageHandler.delete_encrypted_file uses the UUID to find the file
            deleted_from_disk = self.storage_handler.delete_encrypted_file(file_uuid)
            if deleted_from_disk:
                app_logger.info(f"File {file_uuid} (owned by {owner_id_check}) deleted from disk storage.")
            else:
                # This case means the file was in DB but not on disk. Log it.
                app_logger.warning(f"File {file_uuid} (owned by {owner_id_check}) found in DB but not on disk during deletion.")
        except Exception as e: # Catch potential errors from storage handler (e.g., FileStorageError)
            app_logger.error(f"Error deleting file {file_uuid} from disk storage for owner {owner_id_check}: {e}")
            # Depending on policy, you might still want to remove the DB record or halt here.
            # For now, we re-raise to indicate a problem with the deletion process.
            raise RuntimeError(f"Failed to delete file from disk: {e}") 

        # If disk deletion was successful (or policy allows proceeding), delete the database record
        try:
            db.session.delete(file_record)
            db.session.commit()
            app_logger.info(f"File record {file_uuid} (owned by {owner_id_check}) deleted from database.")
        except Exception as e:
            db.session.rollback()
            app_logger.error(f"Error deleting file record {file_uuid} from database for owner {owner_id_check}: {e}")
            # This is a more critical error, as the file might be orphaned on disk if disk deletion succeeded.
            raise RuntimeError(f"Failed to delete file record from database: {e}")

# Add Flask app logger if not already available (e.g. by passing app to FileService or importing current_app)
# For simplicity, assuming app.logger is accessible or you have a logger instance.
# If file_service.py is standalone, you'd set up its own logger.
# For now, we assume it's used within Flask context where app.logger can be found.
# A better way would be to get logger from current_app from flask import current_app; logger = current_app.logger
# For now, to make it runnable as is, if app is not passed to __init__, this logger line would fail.
# Let's assume Flask's app.logger is available via context or passed in.
# This requires `app` to be available, which it is if init_app was called.
app_logger = current_app.logger # Use this instead of app.logger directly if app instance isn't always available 