from typing import Optional, List

class AccessControlList:
    """Manajemen hak akses objek cloud."""
    
    def __init__(self):
        # Data in-memory sementara; nanti diganti dengan database
        self._permissions = {}  # object_id -> {"owner": user_id, "public": bool, "shared_with": {user_id: permission}}
    
    def set_owner(self, object_id: str, owner_id: str):
        if object_id not in self._permissions:
            self._permissions[object_id] = {"owner": owner_id, "public": False, "shared_with": {}}
        else:
            self._permissions[object_id]["owner"] = owner_id
    
    def set_public(self, object_id: str, public: bool):
        self._permissions.setdefault(object_id, {"owner": None, "public": False, "shared_with": {}})
        self._permissions[object_id]["public"] = public
    
    def share_with(self, object_id: str, user_id: str, permission: str = "read"):
        """Berikan akses ke user tertentu (read/write/admin)."""
        self._permissions.setdefault(object_id, {"owner": None, "public": False, "shared_with": {}})
        self._permissions[object_id]["shared_with"][user_id] = permission
    
    def can_access(self, object_id: str, user_id: str, required_perm: str = "read") -> bool:
        """Periksa apakah user memiliki akses required_perm ke objek."""
        if object_id not in self._permissions:
            return False  # Objek tidak ada
        acl = self._permissions[object_id]
        # Owner selalu memiliki akses penuh
        if acl["owner"] == user_id:
            return True
        # Jika publik dan hanya perlu read
        if acl["public"] and required_perm == "read":
            return True
        # Cek daftar shared_with
        shared_perm = acl["shared_with"].get(user_id)
        if shared_perm:
            if shared_perm == "admin":
                return True
            if required_perm == "read" and shared_perm in ("read", "write"):
                return True
            if required_perm == "write" and shared_perm == "write":
                return True
        return False
    
    def revoke_access(self, object_id: str, user_id: str):
        if object_id in self._permissions:
            self._permissions[object_id]["shared_with"].pop(user_id, None)

# Singleton
acl = AccessControlList()