import os
import uuid

# Save uploaded file safely
def save_file(file, upload_folder):
    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder)

    ext = os.path.splitext(file.filename)[1]
    unique_name = f"{uuid.uuid4()}{ext}"
    file_path = os.path.join(upload_folder, unique_name)
    file.save(file_path)

    return file_path


# Temporary write function for scanners
def temp_write(binary_data, upload_folder):
    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder)

    temp_name = f"{uuid.uuid4()}.bin"
    temp_path = os.path.join(upload_folder, temp_name)

    with open(temp_path, "wb") as f:
        f.write(binary_data)

    return temp_path


# Helper: delete file safely
def remove_file(path):
    try:
        if os.path.exists(path):
            os.remove(path)
    except:
        pass


def save_bytes(data: bytes, upload_folder, filename=None):
    """Save bytes to a file in the upload folder."""
    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder)
        
    if not filename:
        filename = f"{uuid.uuid4()}.bin"
        
    file_path = os.path.join(upload_folder, filename)
    
    with open(file_path, "wb") as f:
        f.write(data)
        
    return file_path
