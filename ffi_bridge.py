import ctypes
import os

class MLDSAFFI:
    def __init__(self, lib_path: Optional[str] = None):
        self.lib_path = lib_path or os.environ.get("MLDSA_LIB_PATH")
        if not self.lib_path:
            raise FileNotFoundError("MLDSA_LIB_PATH is not set")
        self.lib = ctypes.CDLL(self.lib_path)

        # These names are placeholders; they must match the actual exported symbols
        self.lib.mldsa_sign.argtypes = [
            ctypes.c_void_p,  # sk
            ctypes.c_void_p,  # msg
            ctypes.c_size_t,
            ctypes.c_void_p,  # sig
            ctypes.POINTER(ctypes.c_size_t),
        ]
        self.lib.mldsa_sign.restype = ctypes.c_int

        self.lib.mldsa_verify.argtypes = [
            ctypes.c_void_p,  # pk
            ctypes.c_void_p,  # msg
            ctypes.c_size_t,
            ctypes.c_void_p,  # sig
            ctypes.c_size_t,
        ]
        self.lib.mldsa_verify.restype = ctypes.c_int

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        sk = ctypes.create_string_buffer(secret_key)
        msg = ctypes.create_string_buffer(message)
        sig = ctypes.create_string_buffer(4096)
        sig_len = ctypes.c_size_t()

        rc = self.lib.mldsa_sign(
            ctypes.byref(sk),
            ctypes.byref(msg),
            len(message),
            ctypes.byref(sig),
            ctypes.byref(sig_len),
        )
        if rc != 0:
            raise RuntimeError(f"mldsa_sign failed with rc={rc}")
        return sig.raw[:sig_len.value]

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        pk = ctypes.create_string_buffer(public_key)
        msg = ctypes.create_string_buffer(message)
        sig = ctypes.create_string_buffer(signature)
        rc = self.lib.mldsa_verify(
            ctypes.byref(pk),
            ctypes.byref(msg),
            len(message),
            ctypes.byref(sig),
            len(signature),
        )
        return rc == 0
