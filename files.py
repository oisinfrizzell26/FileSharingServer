

import os
import uuid
import hashlib
import logging
from pathlib import Path
from typing import Optional, Tuple, BinaryIO
from dataclasses import dataclass
from contextlib import contextmanager

logger = logging.getLogger(__name__)

@dataclass
class FileStorageConfig:
    """Configuration for file storage"""
    uploads_dir: str = "uploads"
    max_file_size: int = 100 * 1024 * 1024  # 100MB default
    use_subdirectories: bool = True
    buffer_size: int = 8192  # 8KB chunks for streaming

class FileStorageError(Exception):
    """Base exception for file storage operations"""
    pass

class FileSizeExceededError(FileStorageError):
    """Raised when file size exceeds limits"""
    pass

class FileNotFoundError(FileStorageError):
    """Raised when requested file doesn't exist"""
    pass

class FileStorageHandler:
    def __init__(self, config: FileStorageConfig = None):
        self.config = config or FileStorageConfig()
        self._ensure_uploads_directory()
    
    def _ensure_uploads_directory(self):
        """Create uploads directory if it doesn't exist"""
        uploads_path = Path(self.config.uploads_dir)
        uploads_path.mkdir(parents=True, exist_ok=True)
        logger.info(f"Uploads directory ensured at: {uploads_path.absolute()}")
    
    def _get_file_path(self, file_uuid: str) -> Path:
        """
        Generate file path from UUID with optional subdirectory structure
        
        Args:
            file_uuid: UUID string for the file
            
        Returns:
            Path object for the file location
        """
        # Validate UUID format
        try:
            uuid.UUID(file_uuid)
        except ValueError:
            raise FileStorageError(f"Invalid UUID format: {file_uuid}")
        
        base_path = Path(self.config.uploads_dir)
        
        if self.config.use_subdirectories:
            # Create subdirectory structure: uploads/a1/b2/a1b2c3d4-...
            subdir1 = file_uuid[:2]
            subdir2 = file_uuid[2:4]
            file_path = base_path / subdir1 / subdir2 / file_uuid
            # Ensure subdirectories exist
            file_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            file_path = base_path / file_uuid
        
        return file_path
    
    def store_encrypted_file(self, file_uuid: str, encrypted_data: bytes) -> Tuple[str, int]:
        """
        Store encrypted file data to disk
        
        Args:
            file_uuid: UUID string for the file
            encrypted_data: Encrypted file content as bytes
            
        Returns:
            Tuple of (file_path_string, file_size)
            
        Raises:
            FileSizeExceededError: If file exceeds size limits
            FileStorageError: If storage operation fails
        """
        if len(encrypted_data) > self.config.max_file_size:
            raise FileSizeExceededError(
                f"File size {len(encrypted_data)} exceeds limit {self.config.max_file_size}"
            )
        
        file_path = self._get_file_path(file_uuid)
        
        try:
            # Write file atomically using temporary file
            temp_path = file_path.with_suffix('.tmp')
            
            with open(temp_path, 'wb') as f:
                f.write(encrypted_data)
                f.flush()
                os.fsync(f.fileno())  # Ensure data is written to disk
            
            # Atomic move to final location
            temp_path.rename(file_path)
            
            file_size = len(encrypted_data)
            logger.info(f"Stored encrypted file: {file_uuid} ({file_size} bytes)")
            
            return str(file_path), file_size
            
        except OSError as e:
            logger.error(f"Failed to store file {file_uuid}: {e}")
            # Clean up temporary file if it exists
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass
            raise FileStorageError(f"Failed to store file: {e}")
    
    def store_encrypted_file_stream(self, file_uuid: str, file_stream: BinaryIO, 
                                   expected_size: Optional[int] = None) -> Tuple[str, int]:
        """
        Store encrypted file from a stream (useful for large files)
        
        Args:
            file_uuid: UUID string for the file
            file_stream: Binary stream to read from
            expected_size: Expected file size for validation (optional)
            
        Returns:
            Tuple of (file_path_string, actual_file_size)
        """
        file_path = self._get_file_path(file_uuid)
        temp_path = file_path.with_suffix('.tmp')
        
        try:
            total_size = 0
            
            with open(temp_path, 'wb') as output_file:
                while True:
                    chunk = file_stream.read(self.config.buffer_size)
                    if not chunk:
                        break
                    
                    total_size += len(chunk)
                    
                    # Check size limit during streaming
                    if total_size > self.config.max_file_size:
                        raise FileSizeExceededError(
                            f"File size exceeds limit {self.config.max_file_size}"
                        )
                    
                    output_file.write(chunk)
                
                output_file.flush()
                os.fsync(output_file.fileno())
            
            # Validate expected size if provided
            if expected_size is not None and total_size != expected_size:
                raise FileStorageError(
                    f"File size mismatch: expected {expected_size}, got {total_size}"
                )
            
            # Atomic move to final location
            temp_path.rename(file_path)
            
            logger.info(f"Stored encrypted file stream: {file_uuid} ({total_size} bytes)")
            return str(file_path), total_size
            
        except Exception as e:
            # Clean up on error
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass
            raise
    
    def retrieve_encrypted_file(self, file_uuid: str) -> bytes:
        """
        Retrieve encrypted file data from disk
        
        Args:
            file_uuid: UUID string for the file
            
        Returns:
            Encrypted file content as bytes
            
        Raises:
            FileNotFoundError: If file doesn't exist
            FileStorageError: If retrieval fails
        """
        file_path = self._get_file_path(file_uuid)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_uuid}")
        
        try:
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            
            logger.info(f"Retrieved encrypted file: {file_uuid} ({len(encrypted_data)} bytes)")
            return encrypted_data
            
        except OSError as e:
            logger.error(f"Failed to retrieve file {file_uuid}: {e}")
            raise FileStorageError(f"Failed to retrieve file: {e}")
    
    @contextmanager
    def retrieve_encrypted_file_stream(self, file_uuid: str):
        """
        Context manager for streaming file retrieval
        
        Args:
            file_uuid: UUID string for the file
            
        Yields:
            Open file handle for reading
            
        Example:
            with handler.retrieve_encrypted_file_stream(uuid) as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    process_chunk(chunk)
        """
        file_path = self._get_file_path(file_uuid)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_uuid}")
        
        try:
            with open(file_path, 'rb') as f:
                yield f
        except OSError as e:
            logger.error(f"Failed to stream file {file_uuid}: {e}")
            raise FileStorageError(f"Failed to stream file: {e}")
    
    def delete_encrypted_file(self, file_uuid: str) -> bool:
        """
        Delete encrypted file from disk
        
        Args:
            file_uuid: UUID string for the file
            
        Returns:
            True if file was deleted, False if file didn't exist
            
        Raises:
            FileStorageError: If deletion fails
        """
        file_path = self._get_file_path(file_uuid)
        
        if not file_path.exists():
            logger.warning(f"Attempted to delete non-existent file: {file_uuid}")
            return False
        
        try:
            file_path.unlink()
            logger.info(f"Deleted encrypted file: {file_uuid}")
            
            # Clean up empty subdirectories if using subdirectory structure
            if self.config.use_subdirectories:
                self._cleanup_empty_directories(file_path.parent)
            
            return True
            
        except OSError as e:
            logger.error(f"Failed to delete file {file_uuid}: {e}")
            raise FileStorageError(f"Failed to delete file: {e}")
    
    def _cleanup_empty_directories(self, directory: Path):
        """Remove empty subdirectories up to uploads_dir"""
        try:
            uploads_path = Path(self.config.uploads_dir).resolve()
            current_dir = directory.resolve()
            
            while current_dir != uploads_path and current_dir != current_dir.parent:
                try:
                    current_dir.rmdir()  # Only removes if empty
                    current_dir = current_dir.parent
                except OSError:
                    # Directory not empty or other error, stop cleanup
                    break
        except Exception as e:
            logger.debug(f"Directory cleanup failed: {e}")
    
    def file_exists(self, file_uuid: str) -> bool:
        """
        Check if file exists on disk
        
        Args:
            file_uuid: UUID string for the file
            
        Returns:
            True if file exists, False otherwise
        """
        try:
            file_path = self._get_file_path(file_uuid)
            return file_path.exists()
        except FileStorageError:
            return False
    
    def get_file_size(self, file_uuid: str) -> int:
        """
        Get size of stored file
        
        Args:
            file_uuid: UUID string for the file
            
        Returns:
            File size in bytes
            
        Raises:
            FileNotFoundError: If file doesn't exist
        """
        file_path = self._get_file_path(file_uuid)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_uuid}")
        
        return file_path.stat().st_size
    
    def get_storage_stats(self) -> dict:
        """
        Get storage statistics
        
        Returns:
            Dictionary with storage statistics
        """
        uploads_path = Path(self.config.uploads_dir)
        
        if not uploads_path.exists():
            return {"total_files": 0, "total_size": 0}
        
        total_files = 0
        total_size = 0
        
        for file_path in uploads_path.rglob("*"):
            if file_path.is_file() and not file_path.name.endswith('.tmp'):
                total_files += 1
                total_size += file_path.stat().st_size
        
        return {
            "total_files": total_files,
            "total_size": total_size,
            "uploads_directory": str(uploads_path.absolute())
        }

# Example usage and testing
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Initialize file storage handler
    config = FileStorageConfig(
        uploads_dir="test_uploads",
        max_file_size=10 * 1024 * 1024,  # 10MB for testing
        use_subdirectories=True
    )
    
    handler = FileStorageHandler(config)
    
    # Test file operations
    test_uuid = str(uuid.uuid4())
    test_data = b"This is encrypted test data" * 1000  # Some test data
    
    try:
        # Store file
        file_path, size = handler.store_encrypted_file(test_uuid, test_data)
        print(f"Stored file at: {file_path} (size: {size})")
        
        # Check if file exists
        exists = handler.file_exists(test_uuid)
        print(f"File exists: {exists}")
        
        # Get file size
        stored_size = handler.get_file_size(test_uuid)
        print(f"Stored file size: {stored_size}")
        
        # Retrieve file
        retrieved_data = handler.retrieve_encrypted_file(test_uuid)
        print(f"Retrieved {len(retrieved_data)} bytes")
        print(f"Data matches: {test_data == retrieved_data}")
        
        # Get storage stats
        stats = handler.get_storage_stats()
        print(f"Storage stats: {stats}")
        
        # Clean up
        deleted = handler.delete_encrypted_file(test_uuid)
        print(f"File deleted: {deleted}")
        
    except FileStorageError as e:
        print(f"Storage error: {e}")