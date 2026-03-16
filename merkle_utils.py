import hashlib
import uuid

def get_hash(data):
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def get_hardware_id():
    """
    Captures the unique MAC address of the machine.
    Binds the evidence seal to the physical hardware.
    """
    return hex(uuid.getnode())

def build_merkle_root(hash_list):
    if not hash_list:
        return "0" * 64
    if len(hash_list) == 1:
        return hash_list[0]
    new_hash_list = []
    for i in range(0, len(hash_list), 2):
        left = hash_list[i]
        right = hash_list[i+1] if i+1 < len(hash_list) else hash_list[i]
        new_hash_list.append(get_hash(left + right))
    return build_merkle_root(new_hash_list)

def generate_investigation_integrity(findings, hw_id=None):
    """
    Generates the integrity seal.
    If hw_id is provided, it is hashed into the leaf list.
    """
    leaf_hashes = []
    for f in findings:
        content = f"{f.get('file_path')}|{f.get('finding_type')}|{f.get('description')}"
        leaf_hashes.append(get_hash(content))
    
    # HARDWARE BINDING: Append HW_ID as a leaf
    if hw_id:
        leaf_hashes.append(get_hash(f"HW_BINDING|{hw_id}"))
    
    leaf_hashes.sort()
    return build_merkle_root(leaf_hashes)