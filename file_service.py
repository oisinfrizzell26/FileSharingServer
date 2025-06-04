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
        logger = current_app.logger
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
        
        try:
            db.session.add(file_record)
            db.session.commit()
            logger.info(f"Stored file {file_uuid} for owner {owner_id} at {file_path}.")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error storing file record {file_uuid} to database: {e}", exc_info=True)
            raise
        
        return file_record
    
    def retrieve_file(self, file_uuid: str) -> bytes:
        """Retrieve file data"""
        logger = current_app.logger
        # Check database record exists
        file_record = Files.query.filter_by(uuid=file_uuid).first()
        if not file_record:
            logger.warning(f"File record with UUID {file_uuid} not found for retrieval.")
            raise FileNotFoundError(f"File record not found: {file_uuid}")
        
        logger.debug(f"Retrieving file from disk path: {file_record.disk_file_path} for UUID {file_uuid}")
        # Retrieve from storage
        return self.storage_handler.retrieve_encrypted_file(file_uuid)
    
    def delete_file(self, file_uuid: str, owner_id_check: int):
        """Delete file from disk and its database record, ensuring ownership."""
        logger = current_app.logger
        # Find the database record first
        file_record = Files.query.filter_by(uuid=file_uuid).first()

        if not file_record:
            logger.info(f"File record with UUID {file_uuid} not found in database for deletion attempt.")
            raise FileNotFoundError(f"File with UUID {file_uuid} not found.")

        # Check ownership
        if file_record.owner_id != owner_id_check:
            logger.warning(f"User {owner_id_check} attempted to delete file {file_uuid} owned by {file_record.owner_id}.")
            raise PermissionError(f"User does not have permission to delete file {file_uuid}.")

        try:
            deleted_from_disk = self.storage_handler.delete_encrypted_file(file_uuid)
            if deleted_from_disk:
                logger.info(f"File {file_uuid} (owned by {owner_id_check}) deleted from disk storage.")
            else:
                logger.warning(f"File {file_uuid} (owned by {owner_id_check}) found in DB but not on disk during deletion.")
        except Exception as e:
            logger.error(f"Error deleting file {file_uuid} from disk storage for owner {owner_id_check}: {e}", exc_info=True)
            raise RuntimeError(f"Failed to delete file from disk: {e}") 

        try:
            db.session.delete(file_record)
            db.session.commit()
            logger.info(f"File record {file_uuid} (owned by {owner_id_check}) deleted from database.")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error deleting file record {file_uuid} from database for owner {owner_id_check}: {e}", exc_info=True)
            raise RuntimeError(f"Failed to delete file record from database: {e}") 