#!/usr/bin/env python3
"""
Production server runner for gobbler.info
"""
from app import app

if __name__ == '__main__':
    # Production configuration
    app.run(
        debug=False,
        host='0.0.0.0',  # Listen on all interfaces
        port=3003,       # Changed from 5000 to avoid AirPlay conflict
        threaded=True    # Handle multiple requests
    ) 