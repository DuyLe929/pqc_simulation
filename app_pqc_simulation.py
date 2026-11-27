import base64
import datetime
import io
import os
import statistics
import sys
import time

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import streamlit as st
from streamlit.web import cli as stcli

# ------------------------------------------------------------------------------
# 0. AUTO-LAUNCH STREAMLIT WHEN RUN VIA: python app_pqc_simulation.py
# ------------------------------------------------------------------------------
if __name__ == "__main__" and not st.runtime.exists():
    PORT = "8888"
    print("=========================================================================")
    print("   KHOI CHAY MO PHONG ML-DSA (NIST FIPS 204)")
    print("=========================================================================")
    print(f"Mo trinh duyet tai: http://localhost:{PORT}  (Ctrl + C de dung)\n")
    sys.argv = ["streamlit", "run", sys.argv[0], "--server.port", PORT]
    sys.exit(stcli.main())

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mldsa, mlkem, padding, rsa
from cryptography.x509.oid import NameOID

import hashlib
import math
from typing import Any

# ------------------------------------------------------------------------------
# 0B. CORE POST-QUANTUM ENGINE (INLINED — SINGLE-FILE STANDALONE APP)
# ------------------------------------------------------------------------------
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87

    HAS_DILITHIUM_PY = True
except ImportError:  # pragma: no cover - defensive fallback
    ML_DSA_44 = ML_DSA_65 = ML_DSA_87 = None
    HAS_DILITHIUM_PY = False


# ------------------------------------------------------------------------------
# 1. VERIFIED NIST FIPS 203 (ML-KEM) & FIPS 204 (ML-DSA) REFERENCE SPECS
# ------------------------------------------------------------------------------
ML_KEM_CLASSES = {
    "ML-KEM-768": mlkem.MLKEM768PrivateKey,
    "ML-KEM-1024": mlkem.MLKEM1024PrivateKey,
}

ML_KEM_PUB_CLASSES = {
    "ML-KEM-768": mlkem.MLKEM768PublicKey,
    "ML-KEM-1024": mlkem.MLKEM1024PublicKey,
}

ML_DSA_CLASSES = {
    "ML-DSA-44": mldsa.MLDSA44PrivateKey,
    "ML-DSA-65": mldsa.MLDSA65PrivateKey,
    "ML-DSA-87": mldsa.MLDSA87PrivateKey,
}

ML_DSA_PUB_CLASSES = {
    "ML-DSA-44": mldsa.MLDSA44PublicKey,
    "ML-DSA-65": mldsa.MLDSA65PublicKey,
    "ML-DSA-87": mldsa.MLDSA87PublicKey,
}

WHITEBOX_SCHEMES = {
    "ML-DSA-44": ML_DSA_44,
    "ML-DSA-65": ML_DSA_65,
    "ML-DSA-87": ML_DSA_87,
}

# Exact NIST FIPS 204 signature packing offsets (bytes)
# sig = c_tilde (c_tilde_bytes) || z (bit_pack_z) || h (k + omega)
ML_DSA_SIG_LAYOUT = {
    "ML-DSA-44": {"c_tilde": 32, "h_tail": 84, "sig_len": 2420},
    "ML-DSA-65": {"c_tilde": 48, "h_tail": 61, "sig_len": 3309},
    "ML-DSA-87": {"c_tilde": 64, "h_tail": 83, "sig_len": 4627},
}


# ------------------------------------------------------------------------------
# 2. HYBRID ML-KEM + ML-DSA MITM PROTOCOL SIMULATION (100% REAL CRYPTO)
# ------------------------------------------------------------------------------
def flip_signature_region(sig: bytes, dsa_name: str, region: str) -> tuple[bytes, int, str]:
    """Flip 1 bit inside a specific FIPS 204 region ('c_tilde', 'z', or 'h')."""
    layout = ML_DSA_SIG_LAYOUT[dsa_name]
    buf = bytearray(sig)
    if region == "c_tilde":
        idx = 0
        label = f"vùng Challenge c_tilde (Byte 0 / {layout['c_tilde']}B)"
    elif region == "z":
        idx = layout["c_tilde"] + 2
        label = f"vùng Vector phản hồi z (Byte {idx})"
    else:
        idx = len(buf) - 1
        label = f"vùng Hint h (Byte {idx} / {layout['h_tail']}B cuối)"
    buf[idx] ^= 0x01
    return bytes(buf), idx, label


def run_hybrid_mitm_simulation(
    kem_name: str,
    dsa_name: str,
    payload_bytes: bytes,
    tampered_payload_bytes: bytes,
    enable_mldsa: bool = True,
    attack_mode: str = "none",
    sig_tamper_region: str = "c_tilde",
    server_id: str = "core-gateway.anm.local",
    enable_mlkem: bool = True,
) -> dict[str, Any]:
    """
    Simulate 3 real-crypto protection modes against an active network Hacker (MITM):
      1. ML-KEM only (enable_mlkem=True, enable_mldsa=False):
         Encrypted with ML-KEM + AES-256-GCM, no server signature -> Hacker swaps pk_KEM,
         decrypts 100% plaintext, and injects forged payload silently.
      2. ML-DSA only (enable_mlkem=False, enable_mldsa=True):
         Signed with ML-DSA, sent without ML-KEM/AES encryption -> Hacker CANNOT tamper/forge
         (ML-DSA blocks), BUT Hacker passively sniffs 100% plaintext!
      3. Full Hybrid (enable_mlkem=True, enable_mldsa=True):
         ML-DSA authenticates (Transcript || pk_KEM), ML-KEM + AES-256-GCM encrypts payload ->
         Both confidentiality and integrity/authentication hold.
    """
    if kem_name not in ML_KEM_CLASSES:
        raise ValueError(f"Unsupported KEM: {kem_name}")
    if dsa_name not in ML_DSA_CLASSES:
        raise ValueError(f"Unsupported DSA: {dsa_name}")

    kem_cls = ML_KEM_CLASSES[kem_name]
    kem_pub_cls = ML_KEM_PUB_CLASSES[kem_name]
    dsa_cls = ML_DSA_CLASSES[dsa_name]

    timeline: list[str] = []
    timings: dict[str, float] = {}

    # ------------------------------------------------------------------
    # MODE: ML-DSA ONLY (NO ML-KEM / NO AES ENCRYPTION)
    # ------------------------------------------------------------------
    if not enable_mlkem:
        t0 = time.perf_counter()
        client_dsa_sk = dsa_cls.generate()
        client_dsa_pk = client_dsa_sk.public_key()
        client_dsa_pk_raw = client_dsa_pk.public_bytes_raw()
        timings["dsa_keygen_ms"] = (time.perf_counter() - t0) * 1000.0

        t0 = time.perf_counter()
        payload_sig = client_dsa_sk.sign(payload_bytes)
        timings["dsa_sign_ms"] = (time.perf_counter() - t0) * 1000.0
        timeline.append(
            f"[CLIENT] Ký trực tiếp gói tin bằng {dsa_name} (Sig={len(payload_sig):,} B, "
            f"{timings['dsa_sign_ms']:.3f} ms) ở dạng bản rõ (chưa mã hóa ML-KEM/AES)."
        )

        # Adversary observes plaintext on the wire
        hacker_sniffed = payload_bytes
        timeline.append(
            f"[MITM] Nghe lén đường truyền -> đọc được toàn bộ bản rõ ({len(hacker_sniffed)} B) "
            "do chưa mã hóa bằng ML-KEM + AES."
        )

        wire_payload = payload_bytes
        wire_sig = payload_sig
        flipped_info = None
        if attack_mode in ("mitm_kem_swap", "mitm_payload"):
            wire_payload = tampered_payload_bytes
            timeline.append(
                "[MITM] Thay đổi nội dung gói tin trên đường truyền (không có Private Key ML-DSA)."
            )
        elif attack_mode == "sig_bitflip":
            wire_sig, flip_idx, flip_label = flip_signature_region(payload_sig, dsa_name, sig_tamper_region)
            flipped_info = {"byte_index": flip_idx, "region": sig_tamper_region, "label": flip_label}
            timeline.append(f"[MITM] Đảo 1 bit trong chữ ký {dsa_name} tại {flip_label}.")

        t0 = time.perf_counter()
        try:
            client_dsa_pk.verify(wire_sig, wire_payload)
            mldsa_ok = True
        except InvalidSignature:
            mldsa_ok = False
        timings["dsa_verify_ms"] = (time.perf_counter() - t0) * 1000.0

        if mldsa_ok:
            timeline.append(
                f"[SERVER] Xác minh {dsa_name} hợp lệ ({timings['dsa_verify_ms']:.3f} ms) -> "
                "Dữ liệu giữ nguyên vẹn, nhưng tính bí mật chưa được bảo vệ trên kênh truyền."
            )
        else:
            timeline.append(
                f"[SERVER] Xác minh {dsa_name} thất bại (InvalidSignature, {timings['dsa_verify_ms']:.3f} ms) -> "
                "Từ chối gói tin đã bị chỉnh sửa (tuy nhiên bản rõ ban đầu vẫn bị lộ khi truyền)."
            )

        total_hs = len(client_dsa_pk_raw) + len(payload_sig)
        return {
            "kem_name": kem_name,
            "dsa_name": dsa_name,
            "enable_mlkem": False,
            "enable_mldsa": True,
            "attack_mode": attack_mode,
            "flipped_info": flipped_info,
            "mldsa_verified": mldsa_ok,
            "handshake_aborted": False,
            "attack_blocked": (attack_mode != "none") and (not mldsa_ok),
            "blocked_by": f"ML-DSA ({dsa_name})" if not mldsa_ok else None,
            "compromised": False,
            "confidentiality_leaked": True,
            "client_ss_hex": None,
            "mallory_ss_hex": None,
            "server_ss_hex": None,
            "mallory_decrypted": hacker_sniffed,
            "server_received": wire_payload if mldsa_ok else None,
            "aes_tag_valid": None,
            "timings": {**timings, "kem_keygen_ms": 0.0, "kem_encap_ms": 0.0, "kem_decap_ms": 0.0},
            "wire_metrics": {
                "pk_kem_bytes": 0,
                "ct_kem_bytes": 0,
                "pk_dsa_bytes": len(client_dsa_pk_raw),
                "sig_dsa_bytes": len(payload_sig),
                "total_handshake_bytes": total_hs,
                "tcp_segments": math.ceil(total_hs / 1460),
                "initcwnd_pct": (total_hs / 14600.0) * 100.0,
            },
            "transcript_sha256_server": hashlib.sha256(payload_bytes).hexdigest()[:24],
            "transcript_sha256_client": hashlib.sha256(wire_payload).hexdigest()[:24],
            "timeline": timeline,
        }

    # 1. Server prepares long-term ML-DSA identity key & ephemeral ML-KEM key
    t0 = time.perf_counter()
    server_kem_sk = kem_cls.generate()
    server_kem_pk = server_kem_sk.public_key()
    server_kem_pk_raw = server_kem_pk.public_bytes_raw()
    timings["kem_keygen_ms"] = (time.perf_counter() - t0) * 1000.0

    t0 = time.perf_counter()
    server_dsa_sk = dsa_cls.generate()
    server_dsa_pk = server_dsa_sk.public_key()
    server_dsa_pk_raw = server_dsa_pk.public_bytes_raw()
    timings["dsa_keygen_ms"] = (time.perf_counter() - t0) * 1000.0

    session_nonce = os.urandom(16)
    server_transcript = (
        f"TLS1.3-PQC-HANDSHAKE||server={server_id}||kem={kem_name}||nonce=".encode("utf-8")
        + session_nonce
        + b"||pk_kem="
        + server_kem_pk_raw
    )
    timeline.append(
        f"[SERVER] Sinh khóa phiên {kem_name} (PK={len(server_kem_pk_raw):,} B) "
        f"trong {timings['kem_keygen_ms']:.3f} ms."
    )

    server_sig: bytes | None = None
    if enable_mldsa:
        t0 = time.perf_counter()
        server_sig = server_dsa_sk.sign(server_transcript)
        timings["dsa_sign_ms"] = (time.perf_counter() - t0) * 1000.0
        timeline.append(
            f"[SERVER] Ký biên bản bắt tay + pk_KEM bằng {dsa_name} "
            f"(Sig={len(server_sig):,} B) trong {timings['dsa_sign_ms']:.3f} ms."
        )
    else:
        timings["dsa_sign_ms"] = 0.0
        timeline.append(
            "[SERVER] Lưu ý: Đang tắt xác thực ML-DSA — khóa pk_KEM được gửi đi không kèm chữ ký."
        )

    # 2. Transit Server -> Client (MITM interception)
    wire_kem_pk_raw = server_kem_pk_raw
    wire_sig = server_sig
    hacker_kem_sk = None
    flipped_info = None

    if attack_mode == "mitm_kem_swap":
        hacker_kem_sk = kem_cls.generate()
        hacker_kem_pk_raw = hacker_kem_sk.public_key().public_bytes_raw()
        wire_kem_pk_raw = hacker_kem_pk_raw
        timeline.append(
            f"[MITM] Chặn gói ServerHello -> thay thế pk_KEM_Server bằng pk_KEM_Adversary "
            f"({len(hacker_kem_pk_raw):,} B)."
        )
    elif attack_mode == "sig_bitflip" and enable_mldsa and wire_sig is not None:
        wire_sig, flip_idx, flip_label = flip_signature_region(wire_sig, dsa_name, sig_tamper_region)
        flipped_info = {"byte_index": flip_idx, "region": sig_tamper_region, "label": flip_label}
        timeline.append(
            f"[MITM] Giữ nguyên pk_KEM nhưng đảo 1 bit chữ ký {dsa_name} tại {flip_label}."
        )

    # 3. Client verifies ML-DSA signature over (Transcript || received pk_KEM)
    client_transcript = (
        f"TLS1.3-PQC-HANDSHAKE||server={server_id}||kem={kem_name}||nonce=".encode("utf-8")
        + session_nonce
        + b"||pk_kem="
        + wire_kem_pk_raw
    )

    mldsa_verified: bool | None = None
    if enable_mldsa:
        t0 = time.perf_counter()
        try:
            assert wire_sig is not None
            server_dsa_pk.verify(wire_sig, client_transcript)
            mldsa_verified = True
        except InvalidSignature:
            mldsa_verified = False
        timings["dsa_verify_ms"] = (time.perf_counter() - t0) * 1000.0

        if not mldsa_verified:
            timeline.append(
                f"[CLIENT] Xác minh {dsa_name} thất bại (InvalidSignature) trong "
                f"{timings['dsa_verify_ms']:.3f} ms."
            )
            timeline.append(
                "[CLIENT] Ngắt kết nối tại bước bắt tay — dừng trước khi đóng gói ML-KEM và không truyền dữ liệu."
            )
            sig_len = len(server_sig) if server_sig else 0
            _, sample_ct = server_kem_pk.encapsulate()
            total_hs = len(server_kem_pk_raw) + len(sample_ct) + len(server_dsa_pk_raw) + sig_len
            return {
                "kem_name": kem_name,
                "dsa_name": dsa_name,
                "enable_mlkem": True,
                "enable_mldsa": enable_mldsa,
                "attack_mode": attack_mode,
                "flipped_info": flipped_info,
                "mldsa_verified": False,
                "handshake_aborted": True,
                "attack_blocked": True,
                "blocked_by": f"ML-DSA ({dsa_name})",
                "compromised": False,
                "confidentiality_leaked": False,
                "client_ss_hex": None,
                "mallory_ss_hex": None,
                "server_ss_hex": None,
                "mallory_decrypted": None,
                "server_received": None,
                "aes_tag_valid": None,
                "timings": {**timings, "kem_encap_ms": 0.0, "kem_decap_ms": 0.0},
                "wire_metrics": {
                    "pk_kem_bytes": len(server_kem_pk_raw),
                    "ct_kem_bytes": len(sample_ct),
                    "pk_dsa_bytes": len(server_dsa_pk_raw),
                    "sig_dsa_bytes": sig_len,
                    "total_handshake_bytes": total_hs,
                    "tcp_segments": math.ceil(total_hs / 1460),
                    "initcwnd_pct": (total_hs / 14600.0) * 100.0,
                },
                "transcript_sha256_server": hashlib.sha256(server_transcript).hexdigest()[:24],
                "transcript_sha256_client": hashlib.sha256(client_transcript).hexdigest()[:24],
                "timeline": timeline,
            }
        timeline.append(
            f"[CLIENT] Xác minh {dsa_name} hợp lệ trong {timings['dsa_verify_ms']:.3f} ms "
            "-> Xác nhận khóa pk_KEM thuộc về Server hợp lệ."
        )
    else:
        timings["dsa_verify_ms"] = 0.0
        timeline.append(
            "[CLIENT] Không có chữ ký ML-DSA để kiểm chứng -> chấp nhận trực tiếp pk_KEM nhận được."
        )

    # 4. Client runs ML-KEM Encapsulation & AES-256-GCM encryption
    received_kem_pk = kem_pub_cls.from_public_bytes(wire_kem_pk_raw)
    t0 = time.perf_counter()
    client_ss, ct_client = received_kem_pk.encapsulate()
    timings["kem_encap_ms"] = (time.perf_counter() - t0) * 1000.0

    aes_nonce = os.urandom(12)
    aes_ct_client = AESGCM(client_ss).encrypt(aes_nonce, payload_bytes, associated_data=b"PQC-DATA")
    timeline.append(
        f"[CLIENT] Đóng gói {kem_name} (CT={len(ct_client):,} B, {timings['kem_encap_ms']:.3f} ms) "
        f"-> Sinh khóa phiên AES-256 `{client_ss[:8].hex()}...` và mã hóa {len(payload_bytes)} B dữ liệu."
    )

    # 5. Transit Client -> Server (Hacker acts if MITM succeeded or payload tamper selected)
    hacker_ss: bytes | None = None
    hacker_decrypted: bytes | None = None
    wire_ct_to_server = ct_client
    wire_nonce_to_server = aes_nonce
    wire_aes_to_server = aes_ct_client

    if attack_mode == "mitm_kem_swap" and not enable_mldsa and hacker_kem_sk is not None:
        hacker_ss = hacker_kem_sk.decapsulate(ct_client)
        assert hacker_ss == client_ss
        hacker_decrypted = AESGCM(hacker_ss).decrypt(aes_nonce, aes_ct_client, associated_data=b"PQC-DATA")
        timeline.append(
            f"[MITM] Giải gói CT bằng sk_KEM_Adversary -> thu được khóa phiên `{hacker_ss[:8].hex()}...`."
        )
        timeline.append(
            f"[MITM] Giải mã được bản rõ ({len(hacker_decrypted)} B) và thay thế bằng nội dung giả mạo."
        )
        hacker_to_server_ss, wire_ct_to_server = server_kem_pk.encapsulate()
        wire_nonce_to_server = os.urandom(12)
        wire_aes_to_server = AESGCM(hacker_to_server_ss).encrypt(
            wire_nonce_to_server, tampered_payload_bytes, associated_data=b"PQC-DATA"
        )
        timeline.append(
            "[MITM] Mã hóa lại gói tin giả mạo bằng khóa phiên lập với Server thật và chuyển tiếp."
        )
    elif attack_mode == "mitm_payload":
        corrupted = bytearray(wire_aes_to_server)
        corrupted[0] ^= 0xFF
        wire_aes_to_server = bytes(corrupted)
        timeline.append(
            "[MITM] Không có khóa phiên nên sửa trực tiếp 1 byte trong bản mã AES-256-GCM trên kênh truyền."
        )

    # 6. Server decapsulates ML-KEM & decrypts AES-256-GCM
    t0 = time.perf_counter()
    server_ss = server_kem_sk.decapsulate(wire_ct_to_server)
    timings["kem_decap_ms"] = (time.perf_counter() - t0) * 1000.0

    server_received: bytes | None = None
    aes_tag_valid = False
    try:
        server_received = AESGCM(server_ss).decrypt(
            wire_nonce_to_server, wire_aes_to_server, associated_data=b"PQC-DATA"
        )
        aes_tag_valid = True
        timeline.append(
            f"[SERVER] Giải gói {kem_name} ({timings['kem_decap_ms']:.3f} ms) và giải mã AES-256-GCM thành công "
            f"(Khóa phiên `{server_ss[:8].hex()}...`)."
        )
    except InvalidTag:
        aes_tag_valid = False
        timeline.append(
            f"[SERVER] Giải gói {kem_name} ({timings['kem_decap_ms']:.3f} ms) nhưng xác thực thẻ AES-256-GCM thất bại (InvalidTag) -> hủy gói tin."
        )

    compromised = (hacker_decrypted is not None) and aes_tag_valid and (server_received != payload_bytes)
    if compromised:
        timeline.append(
            "[KẾT LUẬN] Server tiếp nhận gói tin đã bị chỉnh sửa mà không phát hiện — "
            "cho thấy ML-KEM + AES khi thiếu chữ ký xác thực không ngăn được tấn công MITM tráo khóa."
        )

    attack_blocked = (attack_mode != "none") and (not compromised) and (not aes_tag_valid)
    blocked_by = "AES-256-GCM Integrity Tag" if (attack_mode == "mitm_payload" and not aes_tag_valid) else None

    pk_dsa_len = len(server_dsa_pk_raw) if enable_mldsa else 0
    sig_dsa_len = len(server_sig) if (enable_mldsa and server_sig is not None) else 0
    total_hs = len(server_kem_pk_raw) + len(ct_client) + pk_dsa_len + sig_dsa_len

    return {
        "kem_name": kem_name,
        "dsa_name": dsa_name,
        "enable_mlkem": True,
        "enable_mldsa": enable_mldsa,
        "attack_mode": attack_mode,
        "flipped_info": flipped_info,
        "mldsa_verified": mldsa_verified,
        "handshake_aborted": False,
        "attack_blocked": attack_blocked,
        "blocked_by": blocked_by,
        "compromised": compromised,
        "confidentiality_leaked": hacker_decrypted is not None,
        "client_ss_hex": client_ss.hex(),
        "mallory_ss_hex": hacker_ss.hex() if hacker_ss else None,
        "server_ss_hex": server_ss.hex(),
        "mallory_decrypted": hacker_decrypted,
        "server_received": server_received,
        "aes_tag_valid": aes_tag_valid,
        "timings": timings,
        "wire_metrics": {
            "pk_kem_bytes": len(server_kem_pk_raw),
            "ct_kem_bytes": len(ct_client),
            "pk_dsa_bytes": pk_dsa_len,
            "sig_dsa_bytes": sig_dsa_len,
            "total_handshake_bytes": total_hs,
            "tcp_segments": math.ceil(total_hs / 1460),
            "initcwnd_pct": (total_hs / 14600.0) * 100.0,
        },
        "transcript_sha256_server": hashlib.sha256(server_transcript).hexdigest()[:24],
        "transcript_sha256_client": hashlib.sha256(client_transcript).hexdigest()[:24],
        "timeline": timeline,
    }


# ------------------------------------------------------------------------------
# 3. WHITE-BOX MODULE-LATTICE TRACER (REAL FIPS 204 ALG 7 & 8 VIA DILITHIUM_PY)
# ------------------------------------------------------------------------------
def _centered_coeffs(poly, q: int) -> list[int]:
    half_q = (q - 1) // 2
    return [c - q if c > half_q else c for c in poly.coeffs]


def _vector_inf_norm(vec, q: int) -> int:
    half_q = (q - 1) // 2
    max_val = 0
    for row in vec._data:
        for poly in row:
            for c in poly.coeffs:
                v = abs(c - q if c > half_q else c)
                if v > max_val:
                    max_val = v
    return max_val


def _sample_poly_centered(vec, q: int, count: int = 8) -> list[int]:
    return _centered_coeffs(vec[0, 0], q)[:count]


def trace_keygen_whitebox(dsa_name: str, xi_seed: bytes) -> dict[str, Any]:
    """
    Execute NIST FIPS 204 Algorithm 6 (ML-DSA.KeyGen_internal) transparently from a
    32-byte seed `xi_seed`, returning exact intermediate lattice objects and byte
    layout for both Public Key (rho || t1) and Expanded Private Key (rho||K||tr||s1||s2||t0).
    """
    if not HAS_DILITHIUM_PY or dsa_name not in WHITEBOX_SCHEMES:
        raise RuntimeError(f"dilithium_py unavailable or unsupported scheme: {dsa_name}")
    if len(xi_seed) != 32:
        raise ValueError("FIPS 204 KeyGen seed xi must be exactly 32 bytes.")

    scheme = WHITEBOX_SCHEMES[dsa_name]
    q = scheme.R.q

    # Step 1: SHAKE-256 domain-separated seed expansion: (rho, rho', K) <- H(xi || k || l, 128)
    seed_bytes = scheme._h(xi_seed + bytes([scheme.k, scheme.l]), 128)
    rho, rho_prime, k_seed = seed_bytes[:32], seed_bytes[32:96], seed_bytes[96:]

    # Step 2: Expand public matrix A ∈ R_q^(k x l) and short secret vectors s1, s2
    A_hat = scheme._expand_matrix_from_seed(rho)
    s1, s2 = scheme._expand_vector_from_seed(rho_prime)

    # Step 3: Module-LWE equation t = A*s1 + s2 (mod q), then Power2Round(t, d=13) -> (t1, t0)
    t = (A_hat @ s1.to_ntt()).from_ntt() + s2
    t1, t0 = t.power_2_round(scheme.d)

    # Step 4: Pack PK = rho || t1 and Expanded SK = rho || K || tr || s1 || s2 || t0
    t1_bytes = t1.bit_pack_t1()
    pk_bytes = rho + t1_bytes
    tr = scheme._h(pk_bytes, 64)
    s1_bytes = s1.bit_pack_s(scheme.eta)
    s2_bytes = s2.bit_pack_s(scheme.eta)
    t0_bytes = t0.bit_pack_t0()
    sk_expanded = rho + k_seed + tr + s1_bytes + s2_bytes + t0_bytes

    return {
        "dsa_name": dsa_name,
        "params": {"k": scheme.k, "l": scheme.l, "eta": scheme.eta, "d": scheme.d, "q": q},
        "xi_hex": xi_seed.hex(),
        "rho_hex": rho.hex(),
        "rho_prime_hex": rho_prime.hex(),
        "k_hex": k_seed.hex(),
        "tr_hex": tr.hex(),
        "sk_expanded_hex": sk_expanded.hex(),
        "samples": {
            "s1_0": _sample_poly_centered(s1, q, 6),
            "s2_0": _sample_poly_centered(s2, q, 6),
            "t_0": _sample_poly_centered(t, q, 6),
            "t1_0": _sample_poly_centered(t1, q, 6),
            "t0_0": _sample_poly_centered(t0, q, 6),
        },
        "pk_bytes": pk_bytes,
        "pk_layout": {"rho": len(rho), "t1": len(t1_bytes), "total": len(pk_bytes)},
        "sk_layout": {
            "seed_xi": len(xi_seed),
            "rho": len(rho),
            "K": len(k_seed),
            "tr": len(tr),
            "s1": len(s1_bytes),
            "s2": len(s2_bytes),
            "t0": len(t0_bytes),
            "expanded_total": len(sk_expanded),
        },
    }


def trace_mldsa_whitebox(
    dsa_name: str,
    message_bytes: bytes,
    tamper_target: str = "none",
    deterministic: bool = False,
) -> dict[str, Any]:
    """
    Execute FIPS 204 Algorithm 7 (Sign) & Algorithm 8 (Verify) transparently
    using `dilithium_py`, recording every real Rejection Sampling iteration
    and every verification condition (no hardcoded/simulated lattice logs).

    tamper_target:
      - 'none': verify authentic signature & message
      - 'message': mutate 1 byte of the message before verify
      - 'c_tilde': flip 1 bit in c_tilde region of signature
      - 'z_bound': set a bit in z bytes to push coefficients outside/alter z
      - 'h_hint': flip 1 bit in hint bytes
    """
    if not HAS_DILITHIUM_PY or dsa_name not in WHITEBOX_SCHEMES:
        raise RuntimeError(f"dilithium_py unavailable or unsupported scheme: {dsa_name}")

    scheme = WHITEBOX_SCHEMES[dsa_name]
    q = scheme.R.q
    z_bound = scheme.gamma_1 - scheme.beta
    r0_bound = scheme.gamma_2 - scheme.beta
    ct0_bound = scheme.gamma_2
    omega = scheme.omega
    alpha = scheme.gamma_2 << 1

    # KeyGen (real FIPS 204)
    t0 = time.perf_counter()
    pk, sk = scheme.keygen()
    kg_ms = (time.perf_counter() - t0) * 1000.0

    # Algorithm 2 domain separation (ctx = b"")
    m_prime = b"\x00\x00" + message_bytes
    rnd = bytes(32) if deterministic else os.urandom(32)

    # Algorithm 7: _sign_internal with full per-attempt tracing
    t_sign_start = time.perf_counter()
    rho, k_seed, tr, s1, s2, t0_vec = scheme._unpack_sk(sk)
    s1_hat = s1.to_ntt()
    s2_hat = s2.to_ntt()
    t0_hat = t0_vec.to_ntt()
    A_hat = scheme._expand_matrix_from_seed(rho)

    mu = scheme._h(tr + m_prime, 64)
    rho_prime = scheme._h(k_seed + rnd + mu, 64)

    kappa = 0
    attempt = 0
    attempt_logs: list[dict[str, Any]] = []
    accepted_sample: dict[str, Any] = {}
    sig_bytes = b""

    while True:
        attempt += 1
        cur_kappa = kappa
        y = scheme._expand_mask_vector(rho_prime, kappa)
        y_hat = y.to_ntt()
        w = (A_hat @ y_hat).from_ntt()
        kappa += scheme.l

        w1 = w.high_bits(alpha)
        w1_bytes = w1.bit_pack_w(scheme.gamma_2)
        c_tilde = scheme._h(mu + w1_bytes, scheme.c_tilde_bytes)
        c = scheme.R.sample_in_ball(c_tilde, scheme.tau)
        c_hat = c.to_ntt()

        c_s1 = s1_hat.scale(c_hat).from_ntt()
        z = y + c_s1
        z_norm = _vector_inf_norm(z, q)
        if z.check_norm_bound(z_bound):
            attempt_logs.append(
                {
                    "Lần thử": attempt,
                    "kappa": cur_kappa,
                    "||z||_inf": z_norm,
                    "Ngưỡng z (γ1-β)": z_bound,
                    "||r0||_inf": None,
                    "Ngưỡng r0 (γ2-β)": r0_bound,
                    "||c·t0||_inf": None,
                    "Hint sum(h)": None,
                    "Kết quả": f"ABORT (||z||_inf = {z_norm:,} >= {z_bound:,})",
                }
            )
            continue

        c_s2 = s2_hat.scale(c_hat).from_ntt()
        r0 = (w - c_s2).low_bits(alpha)
        r0_norm = _vector_inf_norm(r0, q)
        if r0.check_norm_bound(r0_bound):
            attempt_logs.append(
                {
                    "Lần thử": attempt,
                    "kappa": cur_kappa,
                    "||z||_inf": z_norm,
                    "Ngưỡng z (γ1-β)": z_bound,
                    "||r0||_inf": r0_norm,
                    "Ngưỡng r0 (γ2-β)": r0_bound,
                    "||c·t0||_inf": None,
                    "Hint sum(h)": None,
                    "Kết quả": f"ABORT (||r0||_inf = {r0_norm:,} >= {r0_bound:,})",
                }
            )
            continue

        c_t0 = t0_hat.scale(c_hat).from_ntt()
        ct0_norm = _vector_inf_norm(c_t0, q)
        if c_t0.check_norm_bound(ct0_bound):
            attempt_logs.append(
                {
                    "Lần thử": attempt,
                    "kappa": cur_kappa,
                    "||z||_inf": z_norm,
                    "Ngưỡng z (γ1-β)": z_bound,
                    "||r0||_inf": r0_norm,
                    "Ngưỡng r0 (γ2-β)": r0_bound,
                    "||c·t0||_inf": ct0_norm,
                    "Hint sum(h)": None,
                    "Kết quả": f"ABORT (||c·t0||_inf = {ct0_norm:,} >= {ct0_bound:,})",
                }
            )
            continue

        h = (-c_t0).make_hint(w - c_s2 + c_t0, alpha)
        h_weight = h.sum_hint()
        if h_weight > omega:
            attempt_logs.append(
                {
                    "Lần thử": attempt,
                    "kappa": cur_kappa,
                    "||z||_inf": z_norm,
                    "Ngưỡng z (γ1-β)": z_bound,
                    "||r0||_inf": r0_norm,
                    "Ngưỡng r0 (γ2-β)": r0_bound,
                    "||c·t0||_inf": ct0_norm,
                    "Hint sum(h)": h_weight,
                    "Kết quả": f"ABORT (sum(h) = {h_weight} > ω={omega})",
                }
            )
            continue

        attempt_logs.append(
            {
                "Lần thử": attempt,
                "kappa": cur_kappa,
                "||z||_inf": z_norm,
                "Ngưỡng z (γ1-β)": z_bound,
                "||r0||_inf": r0_norm,
                "Ngưỡng r0 (γ2-β)": r0_bound,
                "||c·t0||_inf": ct0_norm,
                "Hint sum(h)": h_weight,
                "Kết quả": "ACCEPT (Thỏa mãn toàn bộ biên mạng lưới)",
            }
        )
        sig_bytes = scheme._pack_sig(c_tilde, z, h)
        accepted_sample = {
            "s1_poly0": _sample_poly_centered(s1, q, 8),
            "y_poly0": _sample_poly_centered(y, q, 8),
            "c_poly": _centered_coeffs(c, q)[:16],
            "z_poly0": _sample_poly_centered(z, q, 8),
            "c_tilde_hex": c_tilde.hex(),
            "hint_weight": h_weight,
        }
        break

    sign_ms = (time.perf_counter() - t_sign_start) * 1000.0

    # Cross-check with OpenSSL native verifier before tampering!
    openssl_pub = ML_DSA_PUB_CLASSES[dsa_name].from_public_bytes(pk)
    try:
        openssl_pub.verify(sig_bytes, message_bytes)
        openssl_interop_ok = True
    except InvalidSignature:
        openssl_interop_ok = False

    # Prepare verification input (apply optional tampering)
    verify_msg = message_bytes
    verify_sig = sig_bytes
    tamper_note = "Không can thiệp (dữ liệu & chữ ký nguyên bản)"

    if tamper_target == "message":
        b = bytearray(message_bytes if message_bytes else b"X")
        b[-1] ^= 0x01
        verify_msg = bytes(b)
        tamper_note = "Lật 1 bit ở byte cuối của thông điệp M"
    elif tamper_target == "c_tilde":
        verify_sig, bidx, lbl = flip_signature_region(sig_bytes, dsa_name, "c_tilde")
        tamper_note = f"Lật 1 bit trong {lbl}"
    elif tamper_target == "z_bound":
        # Push the first coefficient of z explicitly beyond (gamma_1 - beta) by re-packing
        c_t_orig, z_orig, h_orig = scheme._unpack_sig(sig_bytes)
        # Modify coefficient 0 of polynomial z[0,0] to gamma_1 - 1 (validly packable in [-gamma_1+1, gamma_1], but >= gamma_1 - beta!)
        bad_coeffs = list(z_orig[0, 0].coeffs)
        bad_coeffs[0] = (scheme.gamma_1 - 1) % q
        z_orig._data[0][0] = scheme.R(bad_coeffs)
        verify_sig = scheme._pack_sig(c_t_orig, z_orig, h_orig)
        tamper_note = (
            f"Thay đổi hệ số z[0][0] = {scheme.gamma_1 - 1:,} "
            f"(vượt ngưỡng an toàn γ1 - β = {z_bound:,})"
        )
    elif tamper_target == "z_bitflip":
        verify_sig, bidx, lbl = flip_signature_region(sig_bytes, dsa_name, "z")
        tamper_note = f"Lật 1 bit trong {lbl} (mà chưa chắc vượt ngưỡng biên)"
    elif tamper_target == "h_hint":
        verify_sig, bidx, lbl = flip_signature_region(sig_bytes, dsa_name, "h")
        tamper_note = f"Lật 1 bit trong {lbl}"

    # Algorithm 8: _verify_internal with transparent step-by-step audit
    t_v0 = time.perf_counter()
    verify_steps: list[dict[str, Any]] = []
    verify_valid = False
    fail_stage = None

    rho_v, t1_v = scheme._unpack_pk(pk)
    unpacked_ok = False
    try:
        c_tilde_v, z_v, h_v = scheme._unpack_sig(verify_sig)
        unpacked_ok = True
    except ValueError as exc:
        verify_steps.append(
            {
                "Bước": "1. Giải nén (c̃, z, h) & kiểm tra Hint",
                "Trạng thái": "FAIL",
                "Chi tiết thật": f"Lỗi cấu trúc mã hóa chữ ký/Hint: {exc}",
            }
        )
        fail_stage = "unpack_error"

    if unpacked_ok:
        h_sum_v = h_v.sum_hint()
        if h_sum_v > omega:
            verify_steps.append(
                {
                    "Bước": "1. Giải nén (c̃, z, h) & kiểm tra Hint",
                    "Trạng thái": "FAIL",
                    "Chi tiết thật": f"Tổng số bit hint sum(h) = {h_sum_v} > ω ({omega})",
                }
            )
            fail_stage = "hint_bound"
        else:
            verify_steps.append(
                {
                    "Bước": "1. Giải nén (c̃, z, h) & kiểm tra Hint",
                    "Trạng thái": "PASS",
                    "Chi tiết thật": f"Giải nén hợp lệ; sum(h) = {h_sum_v} <= ω ({omega})",
                }
            )

            z_norm_v = _vector_inf_norm(z_v, q)
            if z_v.check_norm_bound(z_bound):
                verify_steps.append(
                    {
                        "Bước": "2. Kiểm tra biên chuẩn ||z||_∞ < γ₁ - β",
                        "Trạng thái": "FAIL",
                        "Chi tiết thật": f"VI PHẠM BIÊN LƯỚI: ||z||_∞ = {z_norm_v:,} >= {z_bound:,}",
                    }
                )
                fail_stage = "z_norm_bound"
            else:
                verify_steps.append(
                    {
                        "Bước": "2. Kiểm tra biên chuẩn ||z||_∞ < γ₁ - β",
                        "Trạng thái": "PASS",
                        "Chi tiết thật": f"||z||_∞ = {z_norm_v:,} < {z_bound:,}",
                    }
                )

                A_hat_v = scheme._expand_matrix_from_seed(rho_v)
                tr_v = scheme._h(pk, 64)
                m_prime_v = b"\x00\x00" + verify_msg
                mu_v = scheme._h(tr_v + m_prime_v, 64)
                c_v = scheme.R.sample_in_ball(c_tilde_v, scheme.tau)

                Az_minus_ct1 = ((A_hat_v @ z_v.to_ntt()) - t1_v.scale(1 << scheme.d).to_ntt().scale(c_v.to_ntt())).from_ntt()
                w1_prime = h_v.use_hint(Az_minus_ct1, alpha)
                w1_prime_bytes = w1_prime.bit_pack_w(scheme.gamma_2)
                c_tilde_recomputed = scheme._h(mu_v + w1_prime_bytes, scheme.c_tilde_bytes)

                az_sample = _sample_poly_centered(Az_minus_ct1, q, 6)
                verify_steps.append(
                    {
                        "Bước": "3. Tính đẳng thức mạng lưới A·z - c·t₁·2^d (mod q)",
                        "Trạng thái": "COMPUTED",
                        "Chi tiết thật": f"6 hệ số đầu của (A·z - c·t₁·2^d)[0]: {az_sample}",
                    }
                )

                if c_tilde_v == c_tilde_recomputed:
                    verify_valid = True
                    verify_steps.append(
                        {
                            "Bước": "4. Đối chiếu Challenge c̃' == c̃",
                            "Trạng thái": "PASS",
                            "Chi tiết thật": f"KHỚP 100%: c̃ = c̃' = {c_tilde_recomputed.hex()[:32]}...",
                        }
                    )
                else:
                    fail_stage = "challenge_mismatch"
                    verify_steps.append(
                        {
                            "Bước": "4. Đối chiếu Challenge c̃' == c̃",
                            "Trạng thái": "FAIL",
                            "Chi tiết thật": (
                                f"SAI LỆCH ĐẲNG THỨC LƯỚI! c̃ nhận={c_tilde_v.hex()[:24]}... "
                                f"!= c̃' tính lại={c_tilde_recomputed.hex()[:24]}..."
                            ),
                        }
                    )

    verify_ms = (time.perf_counter() - t_v0) * 1000.0

    # Double-check with scheme.verify()
    lib_verify_ok = scheme.verify(pk, verify_msg, verify_sig)
    assert lib_verify_ok == verify_valid

    return {
        "dsa_name": dsa_name,
        "params": {
            "q": q,
            "k": scheme.k,
            "l": scheme.l,
            "eta": scheme.eta,
            "tau": scheme.tau,
            "beta": scheme.beta,
            "gamma_1": scheme.gamma_1,
            "gamma_2": scheme.gamma_2,
            "omega": omega,
            "d": scheme.d,
            "z_bound": z_bound,
            "r0_bound": r0_bound,
            "pk_bytes": len(pk),
            "sk_bytes": len(sk),
            "sig_bytes": len(sig_bytes),
        },
        "kg_ms": kg_ms,
        "sign_ms": sign_ms,
        "verify_ms": verify_ms,
        "total_attempts": attempt,
        "aborts": attempt - 1,
        "attempt_logs": attempt_logs,
        "accepted_sample": accepted_sample,
        "openssl_interop_ok": openssl_interop_ok,
        "tamper_target": tamper_target,
        "tamper_note": tamper_note,
        "verify_valid": verify_valid,
        "fail_stage": fail_stage,
        "verify_steps": verify_steps,
    }


# ------------------------------------------------------------------------------
# 4. REJECTION SAMPLING EXPERIMENT (FIPS 204 ON vs ABORT BYPASS OFF)
# ------------------------------------------------------------------------------
def experiment_rejection_sampling_leak(
    dsa_name: str = "ML-DSA-44",
    num_samples: int = 40,
) -> dict[str, Any]:
    """
    Run `num_samples` real ML-DSA signings in two modes under the same keypair:
      1. Standard FIPS 204 (Rejection Sampling ON): enforces ||z||_inf < gamma_1 - beta
      2. Broken Bypass (Rejection Sampling OFF): accepts z = y + c*s1 immediately at kappa=0

    Measures:
      - Empirical distribution of centered z coefficients (first polynomial of z)
      - Fraction of coefficients exceeding the safety boundary +/-(gamma_1 - beta)
      - Sign-leak correlation P(sign(z_j) == sign((c*s1)_j)) inside vs outside boundary
      - Empirical distribution of Rejection Sampling attempts (explaining why ML-DSA
        signing latency varies while ML-KEM stays near-constant).
    """
    if not HAS_DILITHIUM_PY or dsa_name not in WHITEBOX_SCHEMES:
        raise RuntimeError(f"dilithium_py unavailable or unsupported scheme: {dsa_name}")

    scheme = WHITEBOX_SCHEMES[dsa_name]
    q = scheme.R.q
    z_bound = scheme.gamma_1 - scheme.beta
    r0_bound = scheme.gamma_2 - scheme.beta
    ct0_bound = scheme.gamma_2
    omega = scheme.omega
    alpha = scheme.gamma_2 << 1

    pk, sk = scheme.keygen()
    rho, k_seed, tr, s1, s2, t0_vec = scheme._unpack_sk(sk)
    s1_hat = s1.to_ntt()
    s2_hat = s2.to_ntt()
    t0_hat = t0_vec.to_ntt()
    A_hat = scheme._expand_matrix_from_seed(rho)

    z_safe_coeffs: list[int] = []
    z_unsafe_coeffs: list[int] = []
    attempts_list: list[int] = []
    abort_reasons = {"z_bound": 0, "r0_bound": 0, "ct0_bound": 0, "hint_bound": 0}

    # Sign agreement counters for boundary-leaking coefficients vs interior coefficients
    boundary_total = 0
    boundary_sign_match = 0
    strict_leak_total = 0
    strict_leak_sign_match = 0
    interior_total = 0
    interior_sign_match = 0
    safe_all_overflow = 0
    unsafe_all_overflow = 0

    t0 = time.perf_counter()
    for idx in range(num_samples):
        m_prime = b"\x00\x00" + f"ML-DSA-RS-EXPERIMENT-{idx}".encode("utf-8")
        mu = scheme._h(tr + m_prime, 64)
        rho_prime = scheme._h(k_seed + os.urandom(32) + mu, 64)

        kappa = 0
        attempts = 0
        while True:
            attempts += 1
            y = scheme._expand_mask_vector(rho_prime, kappa)
            w = (A_hat @ y.to_ntt()).from_ntt()
            kappa += scheme.l

            w1 = w.high_bits(alpha)
            c_tilde = scheme._h(mu + w1.bit_pack_w(scheme.gamma_2), scheme.c_tilde_bytes)
            c = scheme.R.sample_in_ball(c_tilde, scheme.tau)
            c_hat = c.to_ntt()

            c_s1 = s1_hat.scale(c_hat).from_ntt()
            z = y + c_s1

            # Capture attempt #1 as the "Rejection Sampling OFF" sample
            if attempts == 1:
                z_unsafe_coeffs.extend(_centered_coeffs(z[0, 0], q))
                for r_idx in range(scheme.l):
                    z_raw_r = _centered_coeffs(z[r_idx, 0], q)
                    cs1_r = _centered_coeffs(c_s1[r_idx, 0], q)
                    for zv, csv in zip(z_raw_r, cs1_r):
                        if abs(zv) >= z_bound:
                            unsafe_all_overflow += 1
                        if csv == 0 or zv == 0:
                            continue
                        same_sign = (zv > 0 and csv > 0) or (zv < 0 and csv < 0)
                        if abs(zv) > scheme.gamma_1:
                            strict_leak_total += 1
                            if same_sign:
                                strict_leak_sign_match += 1
                        if abs(zv) >= z_bound:
                            boundary_total += 1
                            if same_sign:
                                boundary_sign_match += 1
                        else:
                            interior_total += 1
                            if same_sign:
                                interior_sign_match += 1

            if z.check_norm_bound(z_bound):
                abort_reasons["z_bound"] += 1
                continue

            c_s2 = s2_hat.scale(c_hat).from_ntt()
            r0 = (w - c_s2).low_bits(alpha)
            if r0.check_norm_bound(r0_bound):
                abort_reasons["r0_bound"] += 1
                continue

            c_t0 = t0_hat.scale(c_hat).from_ntt()
            if c_t0.check_norm_bound(ct0_bound):
                abort_reasons["ct0_bound"] += 1
                continue

            h = (-c_t0).make_hint(w - c_s2 + c_t0, alpha)
            if h.sum_hint() > omega:
                abort_reasons["hint_bound"] += 1
                continue

            # Accepted standard FIPS 204 signature
            z_safe_coeffs.extend(_centered_coeffs(z[0, 0], q))
            for r_idx in range(scheme.l):
                for zv in _centered_coeffs(z[r_idx, 0], q):
                    if abs(zv) >= z_bound:
                        safe_all_overflow += 1
            attempts_list.append(attempts)
            break

    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    total_all_coeffs = num_samples * scheme.l * 256

    return {
        "dsa_name": dsa_name,
        "num_samples": num_samples,
        "elapsed_ms": elapsed_ms,
        "gamma_1": scheme.gamma_1,
        "beta": scheme.beta,
        "z_bound": z_bound,
        "z_safe_coeffs": z_safe_coeffs,
        "z_unsafe_coeffs": z_unsafe_coeffs,
        "total_all_coeffs": total_all_coeffs,
        "safe_overflow_count": safe_all_overflow,
        "safe_overflow_pct": (safe_all_overflow / total_all_coeffs) * 100.0 if total_all_coeffs else 0.0,
        "unsafe_overflow_count": unsafe_all_overflow,
        "unsafe_overflow_pct": (unsafe_all_overflow / total_all_coeffs) * 100.0 if total_all_coeffs else 0.0,
        "boundary_total": boundary_total,
        "boundary_sign_match_pct": (boundary_sign_match / boundary_total) * 100.0 if boundary_total else 0.0,
        "strict_leak_total": strict_leak_total,
        "strict_leak_sign_match_pct": (strict_leak_sign_match / strict_leak_total) * 100.0 if strict_leak_total else 0.0,
        "interior_sign_match_pct": (interior_sign_match / interior_total) * 100.0 if interior_total else 0.0,
        "attempts_list": attempts_list,
        "avg_attempts": sum(attempts_list) / len(attempts_list) if attempts_list else 0.0,
        "max_attempts": max(attempts_list) if attempts_list else 0,
        "abort_reasons": abort_reasons,
    }

# ------------------------------------------------------------------------------
# 1. PAGE CONFIG, DESIGN TOKENS & MINIMAL LAB CSS (UI/UX PRO MAX)
# ------------------------------------------------------------------------------
st.set_page_config(
    page_title="ML-DSA (NIST FIPS 204) — Mô phỏng Mật mã Hậu lượng tử",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Semantic color tokens (Academic Dark Lab — Trust Blue + Cyan/Teal + Emerald/Amber/Crimson)
C_BLUE = "#3B82F6"
C_CYAN = "#0EA5E9"
C_TEAL = "#14B8A6"
C_GREEN = "#10B981"
C_AMBER = "#F59E0B"
C_RED = "#EF4444"
C_SLATE = "#64748B"

st.markdown(
    """
    <style>
    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 2.5rem;
        max-width: 1280px;
    }
    h2, h3, h4, h5 {
        letter-spacing: -0.015em;
        font-weight: 600;
    }
    [data-testid="stMetric"] {
        background: rgba(17, 24, 39, 0.78);
        border: 1px solid rgba(148, 163, 184, 0.18);
        border-radius: 8px;
        padding: 11px 14px;
    }
    [data-testid="stMetricValue"] {
        font-variant-numeric: tabular-nums;
        font-size: 1.35rem;
        font-weight: 600;
    }
    [data-testid="stMetricLabel"] {
        font-size: 0.78rem;
        color: #94A3B8;
    }
    [data-testid="stTabs"] button[role="tab"] {
        font-size: 0.9rem;
        font-weight: 500;
        padding: 8px 14px;
    }
    div[data-testid="stExpander"] {
        border: 1px solid rgba(148, 163, 184, 0.16);
        border-radius: 8px;
        background: rgba(17, 24, 39, 0.42);
    }
    code {
        font-variant-numeric: tabular-nums;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Safe session state defaults
_STATE_DEFAULTS = {
    "crypto_keys": None,
    "signature_bytes": None,
    "hybrid_result": None,
    "hybrid_cache_key": None,
    "hybrid_rerun_nonce": 0,
    "whitebox_result": None,
    "rs_exp_result": None,
    "bench_results": None,
    "bench_run_count": 0,
    "bench_timestamp": None,
    "bench_logs": [],
    "pki_results": None,
    "msg_scalability": None,
}
for _k, _v in _STATE_DEFAULTS.items():
    if _k not in st.session_state:
        st.session_state[_k] = _v

MODULES = {
    "ML-DSA-65 (NIST Cấp 3 — Khuyến nghị)": {
        "cls": mldsa.MLDSA65PrivateKey,
        "name": "ML-DSA-65",
        "matrix": "6 x 5",
        "level": "Cấp 3 (192-bit)",
        "target": "Thay thế RSA-3072, AES-192",
        "pk_raw": 1952, "pk_der": 1974, "sk_seed": 32, "sk_der": 54, "sig_len": 3309,
    },
    "ML-DSA-44 (NIST Cấp 2 — Nhẹ nhất)": {
        "cls": mldsa.MLDSA44PrivateKey,
        "name": "ML-DSA-44",
        "matrix": "4 x 4",
        "level": "Cấp 2 (128-bit)",
        "target": "Thay thế RSA-2048, SHA-256",
        "pk_raw": 1312, "pk_der": 1334, "sk_seed": 32, "sk_der": 54, "sig_len": 2420,
    },
    "ML-DSA-87 (NIST Cấp 5 — Tối đa)": {
        "cls": mldsa.MLDSA87PrivateKey,
        "name": "ML-DSA-87",
        "matrix": "8 x 7",
        "level": "Cấp 5 (256-bit)",
        "target": "Thay thế RSA-4096, AES-256",
        "pk_raw": 2592, "pk_der": 2614, "sk_seed": 32, "sk_der": 54, "sig_len": 4627,
    },
}

# ------------------------------------------------------------------------------
# 2. SIDEBAR — TECHNICAL PARAMETERS
# ------------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### Cấu hình ML-DSA")
    st.caption("NIST FIPS 204 · Module-Lattice Digital Signature")

    selected_module_key = st.selectbox(
        "Bộ tham số thí nghiệm",
        list(MODULES.keys()),
        index=0,
    )
    mod_info = MODULES[selected_module_key]

    st.divider()
    st.markdown("**Tham số toán học**")
    st.markdown(
        f"- Ma trận $k \\times \\ell$: `{mod_info['matrix']}`\n"
        f"- Vành đa thức: $R_q = \\mathbb{{Z}}_q[X]/(X^{{256}} + 1)$\n"
        f"- Modulus $q$: `8,380,417`\n"
        f"- Cấp an toàn: `{mod_info['level']}`\n"
        f"- Tương đương: `{mod_info['target']}`"
    )

    st.divider()
    st.markdown("**Kích thước chuẩn NIST**")
    st.markdown(
        f"- Public Key (Raw): **{mod_info['pk_raw']:,} B**\n"
        f"- Signature: **{mod_info['sig_len']:,} B**\n"
        f"- Private Key Seed: **{mod_info['sk_seed']} B**"
    )

# ------------------------------------------------------------------------------
# 2B. SHARED MINIMAL UI HELPERS (PONYTAIL MINDSET)
# ------------------------------------------------------------------------------
def _render_flow_cards(steps: list[tuple]) -> None:
    """Render horizontal Dark-Mode step cards (3-tuple or 5-tuple with Module/Task/Result)."""
    parts = []
    for idx, step in enumerate(steps):
        color, title = step[0], step[1]
        if len(step) == 5:
            mod_badge, task_txt, res_txt = step[2], step[3], step[4]
            body_html = (
                f'<div style="display:inline-block;padding:2px 8px;border-radius:4px;'
                f'background:rgba(15,23,42,0.85);border:1px solid {color};font-size:11px;'
                f'font-weight:600;color:#E2E8F0;margin-bottom:8px;">{mod_badge}</div>'
                f'<div style="font-size:12.5px;line-height:1.5;color:#CBD5E1;margin-bottom:7px;">'
                f'<span style="color:#94A3B8;font-weight:600;">Nhiệm vụ:</span> {task_txt}</div>'
                f'<div style="font-size:12.5px;line-height:1.5;color:#F8FAFC;'
                f'padding-top:7px;border-top:1px solid rgba(148,163,184,0.18);">'
                f'<span style="color:#94A3B8;font-weight:600;">Kết quả:</span> {res_txt}</div>'
            )
        else:
            body_html = f'<div style="font-size:12.8px;line-height:1.5;color:#E2E8F0;">{step[2]}</div>'

        arrow = (
            '<div style="display:flex;align-items:center;font-size:16px;color:#475569;padding:0 2px;">&#8594;</div>'
            if idx < len(steps) - 1
            else ""
        )
        parts.append(
            f'<div style="flex:1;min-width:190px;background:#111827;'
            f'border:1px solid rgba(148,163,184,0.2);border-top:3px solid {color};'
            f'border-radius:8px;padding:12px 14px;">'
            f'<div style="font-size:11px;font-weight:700;letter-spacing:0.04em;color:{color};margin-bottom:6px;">{title}</div>'
            f'{body_html}'
            f'</div>{arrow}'
        )
    st.markdown(
        f'<div style="display:flex;gap:8px;align-items:stretch;margin:10px 0 16px 0;flex-wrap:wrap;">{"".join(parts)}</div>',
        unsafe_allow_html=True,
    )


def _render_byte_bar(segments: list[tuple[str, int, str]]) -> None:
    """Render proportional memory breakdown bar with crisp legend."""
    total = sum(sz for _, sz, _ in segments) or 1
    bars, legends = [], []
    for label, sz, color in segments:
        pct = max(4.0, (sz / total) * 100.0)
        bars.append(
            f'<div title="{label}: {sz:,} B" style="flex:{pct:.2f};background:{color};height:14px;'
            f'display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;'
            f'color:#0B1120;overflow:hidden;white-space:nowrap;">{label if pct >= 16 else ""}</div>'
        )
        legends.append(
            f'<span style="display:inline-flex;align-items:center;gap:5px;margin-right:12px;font-size:12px;color:#CBD5E1;">'
            f'<span style="width:9px;height:9px;border-radius:2px;background:{color};display:inline-block;"></span>'
            f'<b>{label}</b>: {sz:,} B</span>'
        )
    st.markdown(
        f'<div style="display:flex;gap:2px;border-radius:4px;overflow:hidden;margin:6px 0 7px 0;">{"".join(bars)}</div>'
        f'<div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:8px;">{"".join(legends)}</div>',
        unsafe_allow_html=True,
    )


def _style_dark_fig(fig, ax) -> None:
    """Unify Matplotlib figures with the Dark Lab surface palette (WCAG AA contrast)."""
    fig.patch.set_facecolor("#0F172A")
    ax.set_facecolor("#0F172A")
    ax.tick_params(colors="#CBD5E1", labelsize=8.5)
    ax.xaxis.label.set_color("#CBD5E1")
    ax.yaxis.label.set_color("#CBD5E1")
    ax.title.set_color("#F1F5F9")
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    for spine in ("bottom", "left"):
        ax.spines[spine].set_color("#334155")
    ax.grid(axis="y", linestyle="--", color="#334155", alpha=0.55)
    leg = ax.get_legend()
    if leg:
        leg.get_frame().set_facecolor("#1E293B")
        leg.get_frame().set_edgecolor("#334155")
        for txt in leg.get_texts():
            txt.set_color("#E2E8F0")


def _generate_active_keys(info: dict) -> dict:
    """Generate real OpenSSL 3.5 ML-DSA keypair and bit-exact FIPS 204 Alg 6 white-box trace."""
    t0 = time.perf_counter()
    priv = info["cls"].generate()
    kg_time_ms = (time.perf_counter() - t0) * 1000.0
    pub = priv.public_key()
    pub_raw = pub.public_bytes_raw()
    pub_der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    priv_raw = priv.private_bytes_raw()
    priv_der = priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

    kg_trace = trace_keygen_whitebox(info["name"], priv_raw) if HAS_DILITHIUM_PY else None
    bit_exact = (kg_trace is not None) and (kg_trace["pk_bytes"] == pub_raw)
    return {
        "name": info["name"],
        "priv": priv,
        "pub": pub,
        "pub_raw": pub_raw,
        "pub_der": pub_der,
        "priv_raw": priv_raw,
        "priv_der": priv_der,
        "kg_time_ms": kg_time_ms,
        "kg_trace": kg_trace,
        "bit_exact": bit_exact,
    }


def ensure_keys(module_key: str) -> None:
    info = MODULES[module_key]
    cur = st.session_state["crypto_keys"]
    if cur is None or cur["name"] != info["name"] or "kg_trace" not in cur:
        st.session_state["crypto_keys"] = _generate_active_keys(info)
        st.session_state["signature_bytes"] = None
        st.session_state["tab1_sig"] = None


ensure_keys(selected_module_key)

# ------------------------------------------------------------------------------
# 3. HEADER & NAVIGATION TABS (CLEAN ACADEMIC LAB — ZERO EMOJI CLUTTER)
# ------------------------------------------------------------------------------
st.markdown("## Mô phỏng & Đánh giá Thực nghiệm ML-DSA (NIST FIPS 204)")
st.caption(
    "Mật mã học Hậu lượng tử — Sinh khóa Module-Lattice, Kịch bản MITM ML-DSA vs ML-KEM, Đo hiệu năng CPU và Chuỗi PKI X.509."
)

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "1. Sinh khóa",
    "2. Xác thực & Phòng thủ MITM",
    "3. Hiệu năng CPU",
    "4. Chuỗi PKI X.509",
    "5. Độ co giãn tệp",
])

# ==============================================================================
# TAB 1: KEY GENERATION SIMULATION (FIPS 204 ALGORITHM 6)
# ==============================================================================
with tab1:
    st.markdown(f"#### Quy trình Sinh khóa `{mod_info['name']}` (NIST FIPS 204 — Algorithm 6)")
    st.caption(
        "Tính toán trực tiếp từ cùng 1 Seed 32-Byte ξ; Public Key sinh bởi lõi toán học mạng lưới khớp 100% từng bit với OpenSSL Native."
    )

    k = st.session_state["crypto_keys"]
    tr = k.get("kg_trace")

    col_k1, col_k2 = st.columns([1.15, 3])
    with col_k1:
        if st.button("Sinh cặp khóa mới", type="primary", width="stretch"):
            st.session_state["crypto_keys"] = _generate_active_keys(mod_info)
            st.session_state["signature_bytes"] = None
            st.session_state["tab1_sig"] = None
            st.rerun()

    with col_k2:
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Thời gian KeyGen", f"{k['kg_time_ms']:.3f} ms")
        m2.metric("Seed gốc ξ (Lưu đĩa)", f"{len(k['priv_raw'])} B")
        m3.metric("Public Key (Raw)", f"{len(k['pub_raw']):,} B")
        if tr:
            m4.metric("Expanded SK (RAM)", f"{tr['sk_layout']['expanded_total']:,} B")
        else:
            m4.metric("Chữ ký chuẩn", f"{mod_info['sig_len']:,} B")

    if tr:
        p_kg = tr["params"]
        smp = tr["samples"]
        _render_flow_cards([
            (
                C_BLUE,
                "BƯỚC 1 · SINH SEED GỐC (32 B)",
                "SHAKE-256",
                f"Sinh 32 B ngẫu nhiên <code>ξ = {tr['xi_hex'][:10]}...</code> rồi mở rộng thành 3 hạt giống con.",
                "Tạo <code>ρ</code> (dựng ma trận), <code>ρ'</code> (tạo khóa bí mật) và <code>K</code> (dùng khi ký).",
            ),
            (
                C_CYAN,
                f"BƯỚC 2 · MA TRẬN & KHÓA BÍ MẬT",
                f"Ma trận A ({p_kg['k']}×{p_kg['l']})",
                f"Dựng ma trận công khai <b>A</b> từ <code>ρ</code>; sinh vector bí mật nhỏ <b>s₁, s₂</b> ∈ [-{p_kg['eta']}, +{p_kg['eta']}].",
                f"Ví dụ hệ số nhỏ <code>s₁</code>: <code>{smp['s1_0'][:4]}...</code> (giữ tuyệt mật).",
            ),
            (
                C_AMBER,
                "BƯỚC 3 · TÍNH & NÉN KHÓA CÔNG KHAI",
                "t = A·s₁ + s₂ (mod q)",
                "Tính hàm 1 chiều <code>t</code> (khó đảo ngược), rồi cắt lấy bit cao <code>t₁</code> để giảm dung lượng.",
                f"Công bố bit cao <code>t₁</code> (<code>{smp['t1_0'][:3]}...</code>); giữ bit thấp <code>t₀</code> trong SK.",
            ),
            (
                C_GREEN,
                "BƯỚC 4 · ĐÓNG GÓI PK & SK",
                "Khớp 100% OpenSSL",
                "Gộp <code>PK = ρ || t₁</code> để công bố; trên ổ đĩa chỉ cần lưu đúng 32 B Seed <code>ξ</code>.",
                f"PK = <b>{tr['pk_layout']['total']:,} B</b> · Đĩa = <b>32 B</b> · RAM = <b>{tr['sk_layout']['expanded_total']:,} B</b>.",
            ),
        ])

        key_tag = k["pub_raw"][:8].hex()
        col_pub_box, col_priv_box = st.columns(2)
        with col_pub_box:
            st.markdown(f"**Public Key — Khóa công khai (`{tr['pk_layout']['total']:,} B` Raw · `{len(k['pub_der']):,} B` DER)**")
            _render_byte_bar([
                ("ρ (Seed tạo A)", tr["pk_layout"]["rho"], C_CYAN),
                ("t₁ (Bit cao nén)", tr["pk_layout"]["t1"], C_BLUE),
            ])
            st.code(f"Seed ρ (32 B): {tr['rho_hex']}", language="text")
            st.text_area(
                f"Public Key Raw đầy đủ ({len(k['pub_raw']):,} B = {len(k['pub_raw'])*2:,} hex chars)",
                value=k["pub_raw"].hex(),
                height=140,
                key=f"pk_raw_full_{key_tag}",
            )
            st.text_area(
                f"Public Key DER SubjectPublicKeyInfo ({len(k['pub_der']):,} B)",
                value=k["pub_der"].hex(),
                height=95,
                key=f"pk_der_full_{key_tag}",
            )

        with col_priv_box:
            st.markdown(f"**Private Key — Seed `32 B` (`{len(k['priv_der'])} B` DER) → Expanded SK (`{tr['sk_layout']['expanded_total']:,} B` RAM)**")
            skl = tr["sk_layout"]
            _render_byte_bar([
                ("ρ", skl["rho"], C_CYAN),
                ("K", skl["K"], C_BLUE),
                ("tr", skl["tr"], C_AMBER),
                ("s₁", skl["s1"], C_RED),
                ("s₂", skl["s2"], "#FB7185"),
                ("t₀", skl["t0"], C_TEAL),
            ])
            st.code(
                f"Seed ξ (32 B lưu đĩa): {tr['xi_hex']}\n"
                f"Khóa ký nội bộ K     : {tr['k_hex']}",
                language="text",
            )
            st.text_area(
                f"Private Key Expanded đầy đủ ({skl['expanded_total']:,} B = {skl['expanded_total']*2:,} hex chars)",
                value=tr["sk_expanded_hex"],
                height=140,
                key=f"sk_exp_full_{key_tag}",
            )
            st.text_area(
                f"Private Key DER PKCS#8 ({len(k['priv_der']):,} B)",
                value=k["priv_der"].hex(),
                height=95,
                key=f"sk_der_full_{key_tag}",
            )

        st.markdown(
            """
            <div style="background:#0F172A;border:1px solid #1E293B;border-radius:10px;padding:12px 16px;margin:6px 0 12px 0;font-size:13px;line-height:1.65;color:#CBD5E1;">
              <div style="font-weight:700;color:#E2E8F0;margin-bottom:6px;">Chú thích nhanh các ký hiệu trong Public Key &amp; Private Key (FIPS 204)</div>
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:4px 24px;">
                <div><code>ξ</code> <b>(32 B):</b> Seed gốc ngẫu nhiên lưu trên đĩa, tái tạo được toàn bộ cặp khóa.</div>
                <div><code>K</code> <b>(32 B):</b> Khóa nội bộ dùng để trộn tạo số ngẫu nhiên an toàn khi ký.</div>
                <div><code>ρ</code> <b>(32 B):</b> Seed công khai dùng để sinh lại ma trận <b>A</b> (thay vì lưu cả ma trận).</div>
                <div><code>tr</code> <b>(64 B):</b> Mã băm <code>SHAKE-256(PK)</code> gắn Public Key vào chữ ký, chống tráo khóa.</div>
                <div><code>t₁</code> <b>(Bit cao):</b> Phần dữ liệu chính của Public Key sau khi cắt bỏ 13 bit thấp (<code>d=13</code>).</div>
                <div><code>s₁, s₂</code><b>:</b> Hai vector đa thức hệ số nhỏ — thành phần bí mật cốt lõi để ký.</div>
                <div><code>ρ'</code> <b>(64 B):</b> Seed bí mật trung gian dùng trong Bước 2 để sinh <code>s₁, s₂</code>.</div>
                <div><code>t₀</code> <b>(Bit thấp):</b> Phần bit lẻ bị tách khỏi <code>t</code>, lưu trong RAM để hỗ trợ tạo chữ ký.</div>
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        key_tag = k["pub_raw"][:8].hex()
        col_pub_fb, col_priv_fb = st.columns(2)
        with col_pub_fb:
            st.text_area(f"Public Key Raw ({len(k['pub_raw']):,} B)", value=k["pub_raw"].hex(), height=140, key=f"pk_raw_fb_{key_tag}")
            st.text_area(f"Public Key DER ({len(k['pub_der']):,} B)", value=k["pub_der"].hex(), height=95, key=f"pk_der_fb_{key_tag}")
        with col_priv_fb:
            st.text_area(f"Private Seed ξ ({len(k['priv_raw']):,} B)", value=k["priv_raw"].hex(), height=95, key=f"sk_seed_fb_{key_tag}")
            st.text_area(f"Private Key DER PKCS#8 ({len(k['priv_der']):,} B)", value=k["priv_der"].hex(), height=95, key=f"sk_der_fb_{key_tag}")

    # --- LIVE SIGN & VERIFY PLAYGROUND RIGHT INSIDE TAB 1 ---
    st.divider()
    st.markdown(f"#### Ký số & Xác thực thông điệp với `{mod_info['name']}` (kèm Public Key & Private Key)")
    st.caption(
        "Nhập thông điệp bất kỳ, ký bằng cặp khóa hiện tại, xem đầy đủ Public Key / Private Key / Chữ ký và thử sửa 1 ký tự."
    )

    src_key = f"tab1_msg_src_{key_tag}"
    if src_key not in st.session_state:
        st.session_state[src_key] = "Post Quantum Crypto"

    col_sv_l, col_sv_r = st.columns([1.15, 1.85])
    with col_sv_l:
        msg_input = st.text_area(
            "Thông điệp gốc cần ký (Message M)",
            height=90,
            key=src_key,
        )
        if st.button("Ký số thông điệp (Sign)", type="primary", width="stretch", key=f"tab1_sign_btn_{key_tag}"):
            msg_bytes = msg_input.encode("utf-8")
            t_s = time.perf_counter()
            sig_bytes = k["priv"].sign(msg_bytes)
            sign_ms = (time.perf_counter() - t_s) * 1000.0
            pub_pem = k["pub"].public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode("ascii")
            priv_pem = k["priv"].private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            ).decode("ascii")
            st.session_state["tab1_sig"] = {
                "key_tag": key_tag,
                "orig_msg": msg_input,
                "sig": sig_bytes,
                "sign_ms": sign_ms,
                "pub_raw": k["pub_raw"],
                "priv_raw": k["priv_raw"],
                "sk_expanded_bytes": bytes.fromhex(tr["sk_expanded_hex"]) if tr else k["priv_raw"],
                "pub_pem": pub_pem,
                "priv_pem": priv_pem,
            }
            st.session_state[f"tab1_recv_msg_{key_tag}"] = msg_input

    sig_state = st.session_state.get("tab1_sig")
    if sig_state and sig_state.get("key_tag") == key_tag:
        sig_bytes = sig_state["sig"]
        orig_msg = sig_state["orig_msg"]
        layout_s = ML_DSA_SIG_LAYOUT[mod_info["name"]]
        z_len = len(sig_bytes) - layout_s["c_tilde"] - layout_s["h_tail"]

        with col_sv_r:
            recv_key = f"tab1_recv_msg_{key_tag}"
            if recv_key not in st.session_state:
                st.session_state[recv_key] = orig_msg

            c_btn1, c_btn2 = st.columns(2)
            with c_btn1:
                if st.button("Sửa 1 ký tự (Test giả mạo)", width="stretch", key=f"tab1_tamper_btn_{key_tag}"):
                    cur_txt = st.session_state[recv_key]
                    if cur_txt:
                        ch0 = cur_txt[-1]
                        repl = "X" if ch0 != "X" else "Y"
                        st.session_state[recv_key] = cur_txt[:-1] + repl
                    else:
                        st.session_state[recv_key] = "X"
                    st.rerun()
            with c_btn2:
                if st.button("Khôi phục thông điệp gốc", width="stretch", key=f"tab1_restore_btn_{key_tag}"):
                    st.session_state[recv_key] = orig_msg
                    st.rerun()

            recv_msg = st.text_area(
                "Thông điệp phía người nhận dùng để Verify (có thể tự sửa trực tiếp)",
                height=90,
                key=recv_key,
            )

            t_v = time.perf_counter()
            try:
                k["pub"].verify(sig_bytes, recv_msg.encode("utf-8"))
                ver_ms = (time.perf_counter() - t_v) * 1000.0
                is_valid = True
            except InvalidSignature:
                ver_ms = (time.perf_counter() - t_v) * 1000.0
                is_valid = False

            if is_valid:
                st.success(
                    f"XÁC THỰC HỢP LỆ (VALID) · Verify: {ver_ms:.3f} ms · Thông điệp nguyên vẹn 100% và khớp Public Key `{mod_info['name']}`."
                )
            else:
                st.error(
                    f"TỪ CHỐI CHỮ KÝ (InvalidSignature) · Verify: {ver_ms:.3f} ms · Phát hiện thông điệp đã bị thay đổi so với bản gốc đã ký!"
                )

        sm1, sm2, sm3, sm4 = st.columns(4)
        sm1.metric("Thời gian Ký (Sign)", f"{sig_state['sign_ms']:.3f} ms")
        sm2.metric("Thời gian Verify", f"{ver_ms:.3f} ms")
        sm3.metric("Chữ ký σ", f"{len(sig_bytes):,} B")
        sm4.metric("PK / Seed SK", f"{len(sig_state['pub_raw']):,} B / {len(sig_state['priv_raw'])} B")

        _render_byte_bar([
            ("c̃ (Challenge)", layout_s["c_tilde"], C_AMBER),
            ("z (Vector phản hồi)", z_len, C_BLUE),
            ("h (Hint)", layout_s["h_tail"], C_GREEN),
        ])

        fmt = st.radio(
            "Định dạng hiển thị Chữ ký, Public Key & Private Key cho phiên ký này",
            ["Hex", "Base64", "PEM (SPKI / PKCS#8)"],
            horizontal=True,
            key=f"tab1_sig_fmt_{key_tag}",
        )
        sig_disp = sig_bytes.hex() if fmt == "Hex" else base64.b64encode(sig_bytes).decode("ascii")
        sig_unit = "hex chars" if fmt == "Hex" else "Base64 chars"
        st.text_area(
            f"Chữ ký số σ cho thông điệp \"{orig_msg[:48]}\" ({len(sig_bytes):,} B · {len(sig_disp):,} {sig_unit})",
            value=sig_disp,
            height=95,
            key=f"tab1_sig_out_{key_tag}_{fmt}",
        )

        col_kout_pub, col_kout_sk = st.columns(2)
        with col_kout_pub:
            if fmt == "Hex":
                pk_val = sig_state["pub_raw"].hex()
                pk_lbl = f"Public Key (PK) dùng để Verify — Raw Hex ({len(sig_state['pub_raw']):,} B)"
            elif fmt == "Base64":
                pk_val = base64.b64encode(sig_state["pub_raw"]).decode("ascii")
                pk_lbl = f"Public Key (PK) dùng để Verify — Base64 ({len(sig_state['pub_raw']):,} B)"
            else:
                pk_val = sig_state["pub_pem"]
                pk_lbl = f"Public Key (PK) dùng để Verify — PEM SPKI ({len(k['pub_der']):,} B DER)"
            st.text_area(pk_lbl, value=pk_val, height=130, key=f"tab1_msg_pk_{key_tag}_{fmt}")

        with col_kout_sk:
            sk_exp_b = sig_state["sk_expanded_bytes"]
            if fmt == "Hex":
                sk_val = (
                    f"[Seed ξ (32 B lưu đĩa)]\n{sig_state['priv_raw'].hex()}\n\n"
                    f"[Expanded SK ({len(sk_exp_b):,} B trong RAM)]\n{sk_exp_b.hex()}"
                )
                sk_lbl = f"Private Key (SK) đã dùng để Ký — Seed 32 B + Expanded SK ({len(sk_exp_b):,} B) Hex"
            elif fmt == "Base64":
                sk_val = (
                    f"[Seed ξ (32 B lưu đĩa)]\n{base64.b64encode(sig_state['priv_raw']).decode('ascii')}\n\n"
                    f"[Expanded SK ({len(sk_exp_b):,} B trong RAM)]\n{base64.b64encode(sk_exp_b).decode('ascii')}"
                )
                sk_lbl = f"Private Key (SK) đã dùng để Ký — Base64 ({len(sk_exp_b):,} B)"
            else:
                sk_val = sig_state["priv_pem"]
                sk_lbl = f"Private Key (SK) đã dùng để Ký — PEM PKCS#8 ({len(k['priv_der'])} B DER)"
            st.text_area(sk_lbl, value=sk_val, height=130, key=f"tab1_msg_sk_{key_tag}_{fmt}")
    else:
        with col_sv_r:
            st.info("Bấm **Ký số thông điệp (Sign)** bên trái để ký thông điệp, xem đầy đủ **Chữ ký σ + Public Key + Private Key** và kiểm chứng sửa đổi 1 ký tự.")

    with st.expander("Bảng đối chiếu kích thước khóa & payload: Cổ điển vs ML-KEM (FIPS 203) vs ML-DSA (FIPS 204)", expanded=True):
        key_comp_data = [
            {"Thuật toán": "RSA-2048", "Họ / Chuẩn": "Cổ điển (Số lớn)", "Ma trận / Cấp": "112-bit (Phá bởi Shor)", "Public Key": "294 B", "Private Seed / SK": "256 B / 1,216 B", "Chữ ký / Bản mã": "256 B"},
            {"Thuật toán": "ECDSA P-256", "Họ / Chuẩn": "Cổ điển (ECC)", "Ma trận / Cấp": "128-bit (Phá bởi Shor)", "Public Key": "65 B (91 B DER)", "Private Seed / SK": "32 B / 138 B", "Chữ ký / Bản mã": "71 B"},
            {"Thuật toán": "Ed25519", "Họ / Chuẩn": "Cổ điển (Edwards)", "Ma trận / Cấp": "128-bit (Phá bởi Shor)", "Public Key": "32 B (44 B DER)", "Private Seed / SK": "32 B / 48 B", "Chữ ký / Bản mã": "64 B"},
            {"Thuật toán": "ML-KEM-512", "Họ / Chuẩn": "PQC · FIPS 203 (KEM)", "Ma trận / Cấp": "2×2 · Cấp 1 (q=3,329)", "Public Key": "800 B", "Private Seed / SK": "64 B / 1,632 B", "Chữ ký / Bản mã": "768 B (CT)"},
            {"Thuật toán": "ML-KEM-768", "Họ / Chuẩn": "PQC · FIPS 203 (KEM)", "Ma trận / Cấp": "3×3 · Cấp 3 (q=3,329)", "Public Key": "1,184 B", "Private Seed / SK": "64 B / 2,400 B", "Chữ ký / Bản mã": "1,088 B (CT)"},
            {"Thuật toán": "ML-KEM-1024", "Họ / Chuẩn": "PQC · FIPS 203 (KEM)", "Ma trận / Cấp": "4×4 · Cấp 5 (q=3,329)", "Public Key": "1,568 B", "Private Seed / SK": "64 B / 3,168 B", "Chữ ký / Bản mã": "1,568 B (CT)"},
            {"Thuật toán": "ML-DSA-44", "Họ / Chuẩn": "PQC · FIPS 204 (DSA)", "Ma trận / Cấp": "4×4 · Cấp 2 (q=8,380,417)", "Public Key": "1,312 B (1,334 B DER)", "Private Seed / SK": "32 B / 2,560 B", "Chữ ký / Bản mã": "2,420 B (Sig)"},
            {"Thuật toán": "ML-DSA-65", "Họ / Chuẩn": "PQC · FIPS 204 (DSA)", "Ma trận / Cấp": "6×5 · Cấp 3 (q=8,380,417)", "Public Key": "1,952 B (1,974 B DER)", "Private Seed / SK": "32 B / 4,032 B", "Chữ ký / Bản mã": "3,309 B (Sig)"},
            {"Thuật toán": "ML-DSA-87", "Họ / Chuẩn": "PQC · FIPS 204 (DSA)", "Ma trận / Cấp": "8×7 · Cấp 5 (q=8,380,417)", "Public Key": "2,592 B (2,614 B DER)", "Private Seed / SK": "32 B / 4,896 B", "Chữ ký / Bản mã": "4,627 B (Sig)"},
        ]
        st.dataframe(key_comp_data, width="stretch", hide_index=True)

# ==============================================================================
# TAB 2: ML-DSA vs ML-KEM (MITM PROTOCOL) & MODULE-LATTICE WHITE-BOX
# ==============================================================================
with tab2:
    st.markdown("#### Phân tích vai trò bảo mật: `ML-DSA (FIPS 204)` và `ML-KEM (FIPS 203)` trước tấn công MITM")

    scenario_presets = {
        "Định tuyến Core Gateway (10.0.0.1 -> 10.0.0.2)": {
            "short_name": "Cấu hình Router R1",
            "payload": (
                "hostname Core-R1\n"
                "interface GigabitEthernet0/0/0\n"
                " ip address 192.168.1.1 255.255.255.0\n"
                "ip route 0.0.0.0 0.0.0.0 10.0.0.1"
            ),
            "mitm_tamper": (
                "10.0.0.1",
                "10.0.0.2  ! [MITM: Thay doi Gateway]",
            ),
            "server_id": "core-r1.gateway.local",
            "lang": "text",
        },
        "Giao dịch chuyển khoản (A -> B, 50,000,000 VND)": {
            "short_name": "Lệnh chuyển khoản",
            "payload": (
                "LENH CHUYEN KHOAN LIEN NGAN HANG\n"
                "Ma GD   : FT263298812045\n"
                "Tu TK   : 0912345678 - Tai khoan A\n"
                "Den TK  : 1029384756 - Tai khoan B\n"
                "So tien : 50,000,000 VND\n"
                "Noi dung: A chuyen tien cho B"
            ),
            "mitm_tamper": (
                "Den TK  : 1029384756 - Tai khoan B",
                "Den TK  : 9999888877 - [MITM: Sua tai khoan]",
            ),
            "server_id": "api-gateway.bank.local",
            "lang": "text",
        },
    }

    SHOW_TAB_2B = False  # Đổi thành True để bật lại mô phỏng 2B (Module-Lattice White-Box)
    if SHOW_TAB_2B:
        sub_tab_mitm, sub_tab_wb = st.tabs([
            "2A. Kịch bản MITM (ML-KEM vs ML-DSA)",
            "2B. Cấu trúc Module-Lattice (Rejection Sampling)",
        ])
    else:
        sub_tab_mitm, sub_tab_wb = st.container(), None

    # --------------------------------------------------------------------------
    # SUB-TAB 2A: 3-MODE MITM PROTOCOL SIMULATION
    # --------------------------------------------------------------------------
    with sub_tab_mitm:
        st.markdown(
            f'<div style="display:flex;gap:10px;flex-wrap:wrap;margin:2px 0 14px 0;font-size:12.5px;">'
            f'<span style="padding:4px 10px;border-radius:6px;background:#111827;border:1px solid {C_BLUE};color:#E2E8F0;">'
            f'<b style="color:{C_BLUE};">ML-DSA (FIPS 204):</b> Ký xác thực danh tính &amp; chống sửa <i>(không mã hóa)</i></span>'
            f'<span style="padding:4px 10px;border-radius:6px;background:#111827;border:1px solid {C_CYAN};color:#E2E8F0;">'
            f'<b style="color:{C_CYAN};">ML-KEM (FIPS 203):</b> Trao đổi khóa bí mật chung 32B qua mạng</span>'
            f'<span style="padding:4px 10px;border-radius:6px;background:#111827;border:1px solid {C_GREEN};color:#E2E8F0;">'
            f'<b style="color:{C_GREEN};">AES-256-GCM:</b> Dùng khóa 32B của ML-KEM để trực tiếp mã hóa dữ liệu</span>'
            f'</div>',
            unsafe_allow_html=True,
        )

        c_ctrl1, c_ctrl2, c_ctrl3 = st.columns([1.25, 1.45, 1.3])
        with c_ctrl1:
            selected_scenario_name = st.selectbox(
                "1. Kịch bản truyền tin",
                list(scenario_presets.keys()),
                index=0,
                key="hybrid_scenario_sel",
            )
            cur_scenario = scenario_presets[selected_scenario_name]

        with c_ctrl2:
            defense_mode = st.radio(
                "2. Chế độ bảo vệ kênh",
                [
                    "Chỉ ML-KEM + AES (thiếu ML-DSA)",
                    f"Chỉ {mod_info['name']} (thiếu ML-KEM + AES)",
                    f"Đủ cả hai: ML-KEM + {mod_info['name']}",
                ],
                index=0,
                key="hybrid_defense_radio",
            )
            enable_mlkem = not defense_mode.startswith(f"Chỉ {mod_info['name']}")
            enable_mldsa = not defense_mode.startswith("Chỉ ML-KEM")

        with c_ctrl3:
            attack_options = {
                "Tráo khóa công khai KEM / giả mạo (MITM)": "mitm_kem_swap",
                "Không can thiệp (Chỉ nghe lén thụ động)": "none",
                "Sửa 1 byte dữ liệu trên đường truyền": "mitm_payload",
                "Đảo 1 bit chữ ký ML-DSA": "sig_bitflip",
            }
            attack_label = st.radio(
                "3. Kịch bản tấn công (Adversary)",
                list(attack_options.keys()),
                index=0,
                key="hybrid_attack_radio",
            )
            attack_mode = attack_options[attack_label]

        with st.expander("Tùy chỉnh nâng cao (mức ML-KEM, vùng lật bit & nội dung gói tin)", expanded=False):
            ca1, ca2 = st.columns([1, 2])
            with ca1:
                selected_kem = st.selectbox(
                    "Module ML-KEM (FIPS 203)",
                    ["ML-KEM-768", "ML-KEM-1024"],
                    index=0,
                    key="hybrid_kem_sel",
                )
                sig_region = "c_tilde"
                if attack_mode == "sig_bitflip":
                    region_map = {
                        "Vùng Challenge c̃ (đầu chữ ký)": "c_tilde",
                        "Vùng Vector z (giữa chữ ký)": "z",
                        "Vùng Hint h (cuối chữ ký)": "h",
                    }
                    sig_region = region_map[st.selectbox("Vùng lật 1 bit", list(region_map.keys()), key="hybrid_sig_reg")]
                if st.button("Sinh bộ khóa mới & chạy lại", width="stretch"):
                    st.session_state["hybrid_rerun_nonce"] += 1
            with ca2:
                admin_payload = st.text_area(
                    "Nội dung gói tin gốc Client gửi đi",
                    value=cur_scenario["payload"],
                    height=125,
                    key=f"hybrid_payload_{cur_scenario['server_id']}",
                )

        old_part, new_part = cur_scenario["mitm_tamper"]
        tampered_text = (
            admin_payload.replace(old_part, new_part)
            if old_part in admin_payload
            else admin_payload + "\n! [MITM_INJECTED]"
        )

        cache_key = (
            selected_scenario_name, selected_kem, mod_info["name"],
            enable_mlkem, enable_mldsa, attack_mode, sig_region, admin_payload,
            st.session_state["hybrid_rerun_nonce"],
        )
        if st.session_state["hybrid_cache_key"] != cache_key or st.session_state["hybrid_result"] is None:
            res = run_hybrid_mitm_simulation(
                kem_name=selected_kem,
                dsa_name=mod_info["name"],
                payload_bytes=admin_payload.encode("utf-8"),
                tampered_payload_bytes=tampered_text.encode("utf-8"),
                enable_mldsa=enable_mldsa,
                attack_mode=attack_mode,
                sig_tamper_region=sig_region,
                server_id=cur_scenario["server_id"],
                enable_mlkem=enable_mlkem,
            )
            res["original_payload_text"] = admin_payload
            res["lang"] = cur_scenario["lang"]
            st.session_state["hybrid_result"] = res
            st.session_state["hybrid_cache_key"] = cache_key

        hres = st.session_state["hybrid_result"]
        tm = hres["timings"]
        wm = hres["wire_metrics"]

        if not hres["enable_mlkem"]:
            if hres["attack_blocked"]:
                st.warning(
                    f"**ĐẢM BẢO TOÀN VẸN NHƯNG CHƯA BẢO MẬT BÍ MẬT (chỉ có `{hres['dsa_name']}`, thiếu ML-KEM)** — "
                    "ML-DSA từ chối gói tin bị sửa (`InvalidSignature`), nhưng bên thứ ba vẫn đọc được bản rõ do dữ liệu chưa mã hóa."
                )
            else:
                st.warning(
                    f"**CHƯA BẢO MẬT TÍNH BÍ MẬT (chỉ có `{hres['dsa_name']}`, thiếu ML-KEM + AES)** — "
                    "Dữ liệu tới Server nguyên vẹn nhưng truyền ở dạng bản rõ nên bên nghe lén thụ động có thể đọc được toàn bộ nội dung."
                )
        elif hres["compromised"]:
            st.error(
                f"**XÂM NHẬP THÀNH CÔNG (chỉ có `{hres['kem_name']} + AES`, thiếu ML-DSA)** — "
                "Bên tấn công tráo khóa `pk_KEM` thành công, giải mã được bản rõ và chuyển tiếp nội dung giả mạo tới Server."
            )
        elif hres["handshake_aborted"]:
            st.success(
                f"**NGĂN CHẶN TẤN CÔNG — `{hres['dsa_name']}` phát hiện giả mạo trong {tm['dsa_verify_ms']:.3f} ms** — "
                "Client ngắt kết nối ngay tại bước xác minh chữ ký; không phát sinh dữ liệu bản rõ trên đường truyền."
            )
        elif hres["attack_blocked"]:
            st.success(
                f"**PHÁT HIỆN SỬA ĐỔI BẢN MÃ (`{hres['blocked_by']}`)** — "
                "Bên tấn công không có khóa phiên nên làm sai lệch bản mã AES-256-GCM; Server phát hiện `InvalidTag` và hủy gói tin."
            )
        else:
            st.success(
                f"**PHIÊN TRUYỀN TIN AN TOÀN** — `{hres['kem_name']}` + AES-256 bảo mật nội dung"
                + (f" và `{hres['dsa_name']}` xác thực danh tính Server thành công." if hres["enable_mldsa"] else " (kênh sạch, không có can thiệp tráo khóa).")
            )

        pk_kem_b = wm["pk_kem_bytes"]
        ct_kem_b = wm["ct_kem_bytes"]
        sig_dsa_b = wm["sig_dsa_bytes"]
        cli_k_short = f"{hres['client_ss_hex'][:10]}..." if hres["client_ss_hex"] else "—"
        srv_k_short = f"{hres['server_ss_hex'][:10]}..." if hres["server_ss_hex"] else "—"

        if not hres["enable_mlkem"]:
            if hres["attack_blocked"]:
                steps_html = [
                    (C_BLUE, "BƯỚC 1 · KÝ XÁC THỰC", f"{hres['dsa_name']} (Tắt ML-KEM)",
                     "Client ký số lên gói tin để bảo vệ toàn vẹn, nhưng gửi ở dạng <b>bản rõ</b>.",
                     f"Sinh chữ ký <b>{sig_dsa_b:,} B</b> ({tm['dsa_sign_ms']:.2f} ms) — dữ liệu chưa được mã hóa."),
                    (C_AMBER, "BƯỚC 2 · NGHE LÉN BẢN RÕ", "Bên thứ ba (MITM)",
                     "Chặn bắt gói tin trên kênh truyền; do thiếu ML-KEM + AES nên đọc trực tiếp nội dung.",
                     "<b>Đọc được toàn bộ nội dung gốc</b> ngay khi gói tin đi qua mạng."),
                    (C_RED, "BƯỚC 3 · CAN THIỆP GÓI TIN", "Bên thứ ba (MITM)",
                     "Chỉnh sửa nội dung gói tin gửi sang Server nhưng không có Private Key ML-DSA để ký lại.",
                     "Chữ ký cũ không còn hợp lệ đối với nội dung đã sửa."),
                    (C_GREEN, "BƯỚC 4 · XÁC MINH CHỮ KÝ", f"{hres['dsa_name']} (Verify)",
                     "Server dùng Public Key kiểm tra chữ ký trước khi xử lý gói tin.",
                     f"Báo <b>InvalidSignature</b> ({tm['dsa_verify_ms']:.2f} ms) — từ chối gói giả, nhưng bí mật đã lộ ở Bước 2."),
                ]
            else:
                steps_html = [
                    (C_BLUE, "BƯỚC 1 · KÝ XÁC THỰC", f"{hres['dsa_name']} (Tắt ML-KEM)",
                     "Client ký số lên gói tin để đảm bảo toàn vẹn, nhưng <b>không mã hóa nội dung</b>.",
                     f"Gửi bản rõ kèm chữ ký <b>{sig_dsa_b:,} B</b> ({tm['dsa_sign_ms']:.2f} ms)."),
                    (C_AMBER, "BƯỚC 2 · NGHE LÉN THỤ ĐỘNG", "Bên thứ ba (MITM)",
                     "Chỉ nghe lén thụ động trên đường truyền (không thay đổi gói tin).",
                     "<b>Đọc được toàn bộ bản rõ</b> do thiếu tầng mã hóa ML-KEM + AES."),
                    (C_GREEN, "BƯỚC 3 · XÁC MINH CHỮ KÝ", f"{hres['dsa_name']} (Verify)",
                     "Server kiểm tra chữ ký ML-DSA xác nhận nguồn gửi và tính toàn vẹn.",
                     f"Chữ ký hợp lệ ({tm['dsa_verify_ms']:.2f} ms) — dữ liệu không bị sửa."),
                    (C_AMBER, "BƯỚC 4 · ĐÁNH GIÁ AN NINH", "Thiếu mã hóa kênh",
                     "Chỉ đạt Toàn vẹn &amp; Xác thực, chưa bảo vệ tính Bí mật.",
                     "Cần kết hợp thêm <b>ML-KEM + AES-256</b> để mã hóa dữ liệu."),
                ]
        elif hres["compromised"]:
            steps_html = [
                (C_RED, "BƯỚC 1 · GỬI KHÓA CÔNG KHAI KEM", f"{hres['kem_name']} (Tắt ML-DSA)",
                 "Server sinh khóa tạm <code>pk_KEM</code> gửi ra mạng <b>không kèm chữ ký xác thực</b>.",
                 f"Gửi trần <b>{pk_kem_b:,} B</b> — Client chưa có cơ sở xác minh chủ sở hữu khóa."),
                (C_RED, "BƯỚC 2 · CHẶN & THAY KHÓA", "Bên tấn công (MITM)",
                 "Chặn <code>pk_KEM</code> của Server, thay bằng <code>pk_KEM_Adversary</code> gửi cho Client.",
                 "Thiếu ML-DSA kiểm tra — Client <b>chấp nhận nhầm khóa của bên tấn công</b>."),
                (C_RED, "BƯỚC 3 · TRAO KHÓA & MÃ HÓA", f"{hres['kem_name']} -> AES-256",
                 "Client chạy Encapsulate tạo khóa AES-256 và mã hóa gói tin gửi đi.",
                 f"Khóa <code>{cli_k_short}</code> lập với bên tấn công — bên này giải mã và sửa được nội dung."),
                (C_RED, "BƯỚC 4 · CHUYỂN TIẾP DỮ LIỆU GIẢ", "MITM -> Server",
                 "Bên tấn công dùng <code>pk_KEM</code> thật của Server mã hóa lại gói tin giả rồi chuyển tiếp.",
                 f"Server giải mã (<code>{srv_k_short}</code>) và <b>tiếp nhận dữ liệu giả mạo</b> do thiếu xác thực nguồn."),
            ]
        elif hres["handshake_aborted"]:
            act_txt = (
                "Chặn và thay <code>pk_KEM_Server</code> bằng <code>pk_KEM_Adversary</code> (không có khóa bí mật ML-DSA)."
                if hres["attack_mode"] == "mitm_kem_swap"
                else "Giữ nguyên <code>pk_KEM</code> nhưng đảo 1 bit trong chữ ký ML-DSA trên đường truyền."
            )
            steps_html = [
                (C_BLUE, "BƯỚC 1 · TẠO KHÓA & KÝ XÁC THỰC", f"{hres['kem_name']} + {hres['dsa_name']}",
                 "Server tạo khóa tạm <code>pk_KEM</code> và dùng <b>ML-DSA ký xác nhận</b> biên bản bắt tay.",
                 f"Gửi <code>pk_KEM</code> ({pk_kem_b:,} B) + Chữ ký ({sig_dsa_b:,} B) trong {tm['dsa_sign_ms']:.2f} ms."),
                (C_AMBER, "BƯỚC 2 · CAN THIỆP KÊNH TRUYỀN", "Bên tấn công (MITM)",
                 act_txt,
                 "Thông điệp bắt tay bị biến đổi — không còn khớp với chữ ký ML-DSA của Server."),
                (C_GREEN, "BƯỚC 3 · XÁC MINH DANH TÍNH", f"{hres['dsa_name']} (Verify)",
                 "Client kiểm tra chữ ký ML-DSA trên <code>pk_KEM</code> nhận được <b>trước khi đóng gói khóa</b>.",
                 f"Báo <b>InvalidSignature</b> ({tm['dsa_verify_ms']:.2f} ms) — <b>ngắt kết nối</b>."),
                (C_GREEN, "BƯỚC 4 · BẢO TOÀN DỮ LIỆU", "ML-KEM & AES (Chưa thực thi)",
                 "Hủy phiên ngay tại bước bắt tay — không sinh khóa phiên, không truyền dữ liệu.",
                 "<b>Dữ liệu rò rỉ = 0 bytes</b> — ngăn chặn đồng thời nghe lén và giả mạo."),
            ]
        elif hres["attack_blocked"]:
            steps_html = [
                (C_BLUE, "BƯỚC 1 · BẮT TAY THÀNH CÔNG", f"{hres['kem_name']}" + (f" + {hres['dsa_name']}" if hres["enable_mldsa"] else ""),
                 "Client &amp; Server thiết lập an toàn khóa phiên 32B chung qua ML-KEM.",
                 f"Khóa AES-256 trùng khớp: <code>{cli_k_short}</code> (CT = {ct_kem_b:,} B)."),
                (C_BLUE, "BƯỚC 2 · MÃ HÓA DỮ LIỆU", "AES-256-GCM",
                 "Client dùng khóa phiên 32B mã hóa nội dung và gắn thẻ xác thực GCM Tag.",
                 "Dữ liệu truyền trên mạng ở dạng bản mã."),
                (C_AMBER, "BƯỚC 3 · CAN THIỆP BẢN MÃ", "Bên tấn công (MITM)",
                 "Không có khóa phiên để giải mã nên chỉnh sửa ngẫu nhiên 1 byte trong bản mã.",
                 "Làm sai lệch thẻ xác thực toàn vẹn (GCM Tag)."),
                (C_GREEN, "BƯỚC 4 · GIẢI MÃ & KIỂM TRA THẺ", f"{hres['kem_name']} -> AES-256",
                 "Server giải gói khóa phiên và kiểm tra thẻ xác thực AES-256-GCM trước khi giải mã.",
                 "Báo <b>InvalidTag</b> — loại bỏ gói tin bị sửa, không lộ bản rõ."),
            ]
        else:
            b1_mod = f"{hres['kem_name']} + {hres['dsa_name']}" if hres["enable_mldsa"] else f"{hres['kem_name']} (Tắt ML-DSA)"
            b1_task = "Server tạo <code>pk_KEM</code> và dùng <b>ML-DSA ký xác nhận</b> chủ sở hữu." if hres["enable_mldsa"] else "Server tạo <code>pk_KEM</code> gửi trực tiếp (kênh không có can thiệp)."
            b2_mod = f"{hres['dsa_name']} (Verify)" if hres["enable_mldsa"] else "Bỏ qua xác minh"
            b2_task = "Client kiểm tra chữ ký để xác thực <code>pk_KEM</code> thuộc về Server." if hres["enable_mldsa"] else "Không bật ML-DSA nên Client chấp nhận trực tiếp <code>pk_KEM</code>."
            b2_res = f"Xác thực hợp lệ ({tm['dsa_verify_ms']:.2f} ms)." if hres["enable_mldsa"] else "Chỉ an toàn khi không có tấn công tráo khóa."
            steps_html = [
                (C_BLUE, "BƯỚC 1 · KHỞI TẠO PHIÊN", b1_mod, b1_task,
                 f"<code>pk_KEM</code> = {pk_kem_b:,} B" + (f" · Chữ ký = {sig_dsa_b:,} B." if hres["enable_mldsa"] else ".")),
                (C_GREEN if hres["enable_mldsa"] else C_AMBER, "BƯỚC 2 · XÁC THỰC SERVER", b2_mod, b2_task, b2_res),
                (C_CYAN, "BƯỚC 3 · TRAO KHÓA & MÃ HÓA", f"{hres['kem_name']} -> AES-256",
                 "Client chạy Encapsulate tạo khóa chung 32B, sau đó mã hóa bằng <b>AES-256-GCM</b>.",
                 f"Sinh khóa <code>{cli_k_short}</code> ({tm['kem_encap_ms']:.2f} ms), gửi CT ({ct_kem_b:,} B) + bản mã."),
                (C_GREEN, "BƯỚC 4 · GIẢI GÓI & GIẢI MÃ", f"{hres['kem_name']} -> AES-256",
                 "Server chạy Decapsulate khôi phục khóa 32B rồi giải mã AES-256-GCM.",
                 f"Khớp khóa <code>{srv_k_short}</code> ({tm['kem_decap_ms']:.2f} ms) — nhận nguyên vẹn dữ liệu gốc."),
            ]

        _render_flow_cards(steps_html)

        c_cli, c_mal, c_srv = st.columns(3)
        with c_cli:
            st.markdown("**Client gửi đi (Gốc)**")
            st.code(hres["original_payload_text"], language=hres["lang"])
            if hres["client_ss_hex"]:
                st.caption(f"Khóa AES-256 (`{hres['kem_name']}`): `{hres['client_ss_hex'][:16]}...`")
            elif not hres["enable_mlkem"]:
                st.caption("Gửi bản rõ không mã hóa (chỉ kèm chữ ký ML-DSA).")
            else:
                st.caption("Đã dừng ở Bước 3 — không sinh khóa phiên.")

        with c_mal:
            st.markdown("**Bên thứ ba trên kênh truyền (MITM)**")
            if hres["mallory_decrypted"] is not None:
                st.code(hres["mallory_decrypted"].decode("utf-8", errors="replace"), language=hres["lang"])
                if not hres["enable_mlkem"]:
                    st.caption("Đọc được bản rõ do thiếu mã hóa ML-KEM + AES.")
                else:
                    st.caption(f"Thiết lập được khóa giả mạo: `{hres['mallory_ss_hex'][:16]}...`")
            elif hres["handshake_aborted"]:
                st.code("[PHIÊN BỊ HỦY TẠI BƯỚC XÁC MINH ML-DSA]\nDữ liệu thu được: 0 bytes", language="text")
                st.caption("Kết nối bị ngắt trước khi thiết lập khóa phiên.")
            else:
                st.code("[CHỈ QUAN SÁT ĐƯỢC BẢN MÃ AES-256-GCM]\nKhông giải mã được", language="text")
                st.caption("Tính bí mật được bảo vệ bởi ML-KEM + AES.")

        with c_srv:
            st.markdown("**Dữ liệu Server tiếp nhận**")
            if hres["server_received"] is not None:
                st.code(hres["server_received"].decode("utf-8", errors="replace"), language=hres["lang"])
                if hres["compromised"]:
                    st.caption("Tiếp nhận dữ liệu đã bị chỉnh sửa do thiếu xác thực ML-DSA.")
                elif not hres["enable_mlkem"]:
                    st.caption("Nội dung toàn vẹn nhưng đã bị nghe lén trên kênh truyền.")
                else:
                    st.caption(f"Khớp dữ liệu gốc (Khóa `{hres['server_ss_hex'][:16]}...`)")
            else:
                st.code("[ĐÃ HỦY GÓI TIN / PHIÊN]\nTừ chối xử lý dữ liệu không hợp lệ", language="text")
                st.caption("Tính toàn vẹn được bảo vệ thành công.")

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Tải ML-KEM (PK + CT)", f"{wm['pk_kem_bytes'] + wm['ct_kem_bytes']:,} B" if hres["enable_mlkem"] else "Tắt")
        m2.metric("Tải ML-DSA (PK + Sig)", f"{wm['pk_dsa_bytes'] + wm['sig_dsa_bytes']:,} B" if hres["enable_mldsa"] else "Tắt")
        m3.metric("Tổng tải bắt tay", f"{wm['total_handshake_bytes']:,} B")
        m4.metric("Thời gian Verify ML-DSA", f"{tm['dsa_verify_ms']:.3f} ms" if hres["enable_mldsa"] else "Tắt")

        with st.expander("Nhật ký giao thức chi tiết (Protocol Trace)"):
            st.code("\n".join(hres["timeline"]), language="shell")

    # --------------------------------------------------------------------------
    # SUB-TAB 2B: MODULE-LATTICE WHITE-BOX & REJECTION SAMPLING (TEMPORARILY OFF)
    # --------------------------------------------------------------------------
    if SHOW_TAB_2B and sub_tab_wb is not None:
        with sub_tab_wb:
            _render_flow_cards([
                (C_BLUE, "BƯỚC 1 · MẶT NẠ NGẪU NHIÊN", "ExpandMask (SHAKE-256)",
                 "Sinh vector mặt nạ ngẫu nhiên <b>y</b> cho vòng <code>kappa</code> và tính cam kết <code>w = A·y</code>.",
                 "Mỗi lần thử tạo một lớp che <b>y</b> mới để giấu khóa bí mật."),
                (C_CYAN, "BƯỚC 2 · TẠO THỬ THÁCH", "SampleInBall",
                 "Băm nội dung thông điệp cùng phần cao của <code>w</code> ra đa thức thử thách <b>c</b>.",
                 "Thu được đa thức thưa <b>c</b> chỉ gồm các hệ số <code>-1, 0, 1</code>."),
                (C_BLUE, "BƯỚC 3 · TÍNH PHẢN HỒI", "Module-Lattice (q = 8,380,417)",
                 "Trộn mặt nạ với khóa bí mật <b>s₁</b> qua công thức <code>z = y + c·s₁</code>.",
                 "Tạo ứng viên chữ ký <b>z</b> gắn chặt khóa bí mật với thông điệp."),
                (C_AMBER, "BƯỚC 4 · CỔNG LỌC ABORT", "Rejection Sampling",
                 "Kiểm tra biên <code>||z||_∞ &lt; γ₁ - β</code> và <code>||r₀||_∞ &lt; γ₂ - β</code> để không rò rỉ <b>s₁</b>.",
                 "Nếu chạm biên: <b>ABORT</b> quay lại Bước 1; nếu lọt: <b>ACCEPT</b> xuất chữ ký."),
            ])
            st.caption(
                "Điểm khác biệt gốc với ML-KEM: `ML-KEM` chạy thẳng 1 lượt không cần Bước 4; "
                "`ML-DSA` bắt buộc lặp Bước 4 (trung bình ~4–5 vòng) để giấu khóa bí mật $s_1$."
            )

            if not HAS_DILITHIUM_PY:
                st.error("Chưa cài thư viện `dilithium-py`. Vui lòng chạy `pip install dilithium-py`.")
            else:
                st.markdown("##### Phần 1. Phân tích 1 lần Ký & Xác minh FIPS 204 (`dilithium_py` + OpenSSL 3.5)")
                col_wb1, col_wb2, col_wb3 = st.columns([1.8, 1.5, 1.1])
                with col_wb1:
                    wb_msg = st.text_input(
                        "Thông điệp M cần ký",
                        value="ip route 0.0.0.0 0.0.0.0 10.0.0.1",
                        key="wb_msg_input",
                    )
                with col_wb2:
                    tamper_choices = {
                        "Không can thiệp (hợp lệ 100%)": "none",
                        "Đẩy z vượt biên γ₁ - β (chặn tại bước Norm)": "z_bound",
                        "Lật 1 bit Challenge c̃ (sai đẳng thức lưới)": "c_tilde",
                        "Sửa 1 bit thông điệp M": "message",
                        "Lật 1 bit Hint h (lỗi giải nén Hint)": "h_hint",
                    }
                    wb_tamper_target = tamper_choices[st.selectbox("Kiểm thử can thiệp toán học", list(tamper_choices.keys()))]
                with col_wb3:
                    st.write("")
                    run_wb = st.button(f"Phân tích {mod_info['name']}", type="primary", width="stretch")

                if run_wb or st.session_state["whitebox_result"] is None:
                    st.session_state["whitebox_result"] = trace_mldsa_whitebox(
                        dsa_name=mod_info["name"],
                        message_bytes=wb_msg.encode("utf-8"),
                        tamper_target=wb_tamper_target,
                    )

                wb = st.session_state["whitebox_result"]
                p = wb["params"]
                w1, w2, w3, w4 = st.columns(4)
                w1.metric("Ma trận lưới A", f"{p['k']} x {p['l']}", delta=f"{wb['dsa_name']} (q=8,380,417)")
                w2.metric("Số vòng lặp kappa", f"{wb['total_attempts']} lượt", delta=f"{wb['aborts']} ABORT · 1 ACCEPT")
                w3.metric("Ngưỡng an toàn |z|", f"< {p['z_bound']:,}", delta=f"γ₁={p['gamma_1']:,}, β={p['beta']}")
                w4.metric("Đối chiếu OpenSSL 3.5", "VALID 100%" if wb["openssl_interop_ok"] else "MISMATCH")

                badges = []
                for row in wb["attempt_logs"]:
                    is_acc = row["Kết quả"].startswith("ACCEPT")
                    bg = "rgba(16,185,129,0.16)" if is_acc else "rgba(239,68,68,0.14)"
                    bd = C_GREEN if is_acc else C_RED
                    lbl = "ACCEPT" if is_acc else f"ABORT ({row['Kết quả'].split('(')[1].split('=')[0].strip()})"
                    badges.append(
                        f'<span style="display:inline-block;margin:3px 6px 3px 0;padding:3px 10px;'
                        f'border-radius:4px;background:{bg};border:1px solid {bd};font-size:12px;color:#F8FAFC;">'
                        f'Vòng {row["Lần thử"]} (κ={row["kappa"]}): <b>{lbl}</b></span>'
                    )
                st.markdown(f'<div style="margin:6px 0 12px 0;">{"".join(badges)}</div>', unsafe_allow_html=True)

                if wb["verify_valid"]:
                    st.success(f"**VERIFY HỢP LỆ** ({wb['verify_ms']:.1f} ms) — *{wb['tamper_note']}*")
                else:
                    st.error(f"**VERIFY TỪ CHỐI tại `{wb['fail_stage']}`** ({wb['verify_ms']:.1f} ms) — *{wb['tamper_note']}*")
                st.dataframe(wb["verify_steps"], width="stretch", hide_index=True)

                with st.expander("Chi tiết từng vòng kappa & mẫu hệ số đa thức thật (s₁, y, c, z)"):
                    st.dataframe(wb["attempt_logs"], width="stretch", hide_index=True)
                    samp = wb["accepted_sample"]
                    st.markdown(
                        f"- **$s_1[0]$ (bí mật, biên $\\pm{p['eta']}$):** `{samp['s1_poly0']}`\n"
                        f"- **$y[0]$ (mặt nạ ngẫu nhiên):** `{samp['y_poly0']}`\n"
                        f"- **$c$ (thử thách thưa, $\\tau={p['tau']}$):** `{samp['c_poly']}`\n"
                        f"- **$z[0] = (y + c\\cdot s_1)[0]$ (chữ ký):** `{samp['z_poly0']}`"
                    )

                st.divider()
                st.markdown("##### Phần 2. Thí nghiệm Bật vs Tắt Rejection Sampling")
                col_rs1, col_rs2 = st.columns([1.4, 2])
                with col_rs1:
                    rs_samples = st.slider(
                        "Số lượng chữ ký thí nghiệm thật",
                        min_value=20,
                        max_value=80,
                        value=40,
                        step=10,
                        key="rs_samples_slider",
                    )
                with col_rs2:
                    st.write("")
                    run_rs = st.button(
                        f"Chạy thí nghiệm Rejection Sampling ({mod_info['name']})",
                        type="primary",
                        width="stretch",
                    )

                if run_rs:
                    with st.spinner(f"Đang ký thật {rs_samples} thông điệp trên {mod_info['name']}..."):
                        st.session_state["rs_exp_result"] = experiment_rejection_sampling_leak(
                            dsa_name=mod_info["name"],
                            num_samples=rs_samples,
                        )

                rse = st.session_state.get("rs_exp_result")
                if rse:
                    rm1, rm2, rm3, rm4 = st.columns(4)
                    rm1.metric("Vòng lặp TB (ML-DSA)", f"{rse['avg_attempts']:.2f} lượt", delta="ML-KEM luôn = 1 lượt")
                    rm2.metric("Tràn biên (BẬT FIPS 204)", f"{rse['safe_overflow_count']}", delta="0.000% (An toàn)")
                    rm3.metric("Tràn biên (TẮT Rejection)", f"{rse['unsafe_overflow_count']} hệ số", delta=f"{rse['unsafe_overflow_pct']:.3f}% rò biên", delta_color="inverse")
                    rm4.metric("Trùng dấu s₁ vùng biên", f"{rse['boundary_sign_match_pct']:.1f}%", delta=f"Vùng an toàn ~{rse['interior_sign_match_pct']:.1f}%")

                    col_rsc1, col_rsc2 = st.columns(2)
                    with col_rsc1:
                        zb, g1, beta = rse["z_bound"], rse["gamma_1"], rse["beta"]
                        zoom_min = zb - 4 * beta
                        safe_tail = [abs(v) for v in rse["z_safe_coeffs"] if abs(v) >= zoom_min]
                        unsafe_tail = [abs(v) for v in rse["z_unsafe_coeffs"] if abs(v) >= zoom_min]

                        fig_rs1, ax_rs1 = plt.subplots(figsize=(6.4, 3.8))
                        bins = np.linspace(zoom_min, g1 + beta, 26)
                        ax_rs1.hist(unsafe_tail, bins=bins, alpha=0.65, color=C_RED, label="TẮT Rejection (tràn biên, lộ s₁)")
                        ax_rs1.hist(safe_tail, bins=bins, alpha=0.78, color=C_GREEN, label="BẬT FIPS 204 (cắt tại γ₁-β)")
                        ax_rs1.axvline(zb, color="#E2E8F0", linestyle="--", linewidth=1.4, label=f"Ngưỡng γ₁ - β = {zb:,}")
                        ax_rs1.axvline(g1, color=C_AMBER, linestyle=":", linewidth=1.4, label=f"Ngưỡng γ₁ = {g1:,}")
                        ax_rs1.set_xlabel("Trị tuyệt đối hệ số |z| vùng sát biên")
                        ax_rs1.set_ylabel("Số lượng hệ số (z[0])")
                        ax_rs1.set_title(f"Phân phối vùng biên |z| ({rse['dsa_name']}, N={rse['num_samples']})", fontsize=10, fontweight="bold")
                        ax_rs1.legend(fontsize=7.5, loc="upper right")
                        _style_dark_fig(fig_rs1, ax_rs1)
                        fig_rs1.tight_layout()
                        st.pyplot(fig_rs1)
                        plt.close(fig_rs1)

                    with col_rsc2:
                        fig_rs2, ax_rs2 = plt.subplots(figsize=(6.4, 3.8))
                        max_a = max(rse["attempts_list"])
                        att_bins = np.arange(1, max_a + 2) - 0.5
                        ax_rs2.hist(rse["attempts_list"], bins=att_bins, color=C_BLUE, edgecolor="#0F172A", alpha=0.88, label="ML-DSA (Phân phối hình học)")
                        ax_rs2.axvline(1, color=C_GREEN, linestyle="--", linewidth=1.8, label="ML-KEM (Luôn đúng 1 lượt)")
                        ax_rs2.axvline(rse["avg_attempts"], color=C_AMBER, linestyle="-.", linewidth=1.6, label=f"TB ML-DSA = {rse['avg_attempts']:.2f}")
                        ax_rs2.set_xlabel("Số vòng thử kappa để sinh 1 chữ ký")
                        ax_rs2.set_ylabel("Số chữ ký")
                        ax_rs2.set_title("Số vòng lặp sinh chữ ký: ML-DSA vs ML-KEM", fontsize=10, fontweight="bold")
                        ax_rs2.legend(fontsize=8, loc="upper right")
                        _style_dark_fig(fig_rs2, ax_rs2)
                        fig_rs2.tight_layout()
                        st.pyplot(fig_rs2)
                        plt.close(fig_rs2)

                    ab = rse["abort_reasons"]
                    st.info(
                        f"**Tóm tắt ({rse['dsa_name']}):** Số lần ABORT theo nguyên nhân — `||z||`: **{ab['z_bound']}**, "
                        f"`||r0||`: **{ab['r0_bound']}**, `||c·t0||`: **{ab['ct0_bound']}**, `hint`: **{ab['hint_bound']}**. "
                        "Tắt Rejection Sampling khiến hệ số tràn biên $\\gamma_1 - \\beta$ làm rò rỉ dấu khóa bí mật $s_1$."
                    )

# ==============================================================================
# TAB 3: CPU MICRO-BENCHMARK (CLASSICAL SIGNATURES vs ML-DSA)
# ==============================================================================
with tab3:
    st.markdown("#### Đo đạc hiệu năng CPU thực tế: Chữ ký số Cổ điển vs ML-DSA")
    cpu_cores = os.cpu_count() or 4
    st.caption(f"Môi trường: x86_64 ({cpu_cores} logical cores) · Python {sys.version.split()[0]} · OpenSSL Native (kèm 1 vòng warm-up).")

    col_bench_run, col_bench_cfg, col_bench_stat = st.columns([1, 1, 1])
    with col_bench_run:
        runs_count = st.slider("Số vòng lặp (lấy Median)", min_value=10, max_value=100, value=30, step=10)
    with col_bench_cfg:
        chart_mode = st.radio("Biểu đồ thứ 2", ["Thông lượng CPU (ops/s)", "Kích thước khóa & chữ ký (Bytes)"], index=0)
    with col_bench_stat:
        st.write("")
        start_bench = st.button("Chạy đo hiệu năng CPU", type="primary", width="stretch")

    log_container = st.empty()
    progress_bar = st.empty()

    if start_bench:
        st.session_state["bench_run_count"] += 1
        run_id = st.session_state["bench_run_count"]
        now_str = datetime.datetime.now().strftime("%H:%M:%S (%d/%m/%Y)")
        st.session_state["bench_timestamp"] = now_str

        bench_msg = b"Benchmark Network Security NIST FIPS 204"
        bench_targets = [
            ("RSA-2048", lambda: (lambda k: (k, k.public_key()))(rsa.generate_private_key(65537, 2048)),
             lambda k, m: k.sign(m, padding.PKCS1v15(), hashes.SHA256()),
             lambda p, s, m: p.verify(s, m, padding.PKCS1v15(), hashes.SHA256()), 294, 256, max(5, runs_count // 3)),
            ("RSA-3072", lambda: (lambda k: (k, k.public_key()))(rsa.generate_private_key(65537, 3072)),
             lambda k, m: k.sign(m, padding.PKCS1v15(), hashes.SHA256()),
             lambda p, s, m: p.verify(s, m, padding.PKCS1v15(), hashes.SHA256()), 422, 384, max(3, runs_count // 6)),
            ("ECDSA P-256", lambda: (lambda k: (k, k.public_key()))(ec.generate_private_key(ec.SECP256R1())),
             lambda k, m: k.sign(m, ec.ECDSA(hashes.SHA256())),
             lambda p, s, m: p.verify(s, m, ec.ECDSA(hashes.SHA256())), 91, 71, runs_count),
            ("Ed25519", lambda: (lambda k: (k, k.public_key()))(ed25519.Ed25519PrivateKey.generate()),
             lambda k, m: k.sign(m), lambda p, s, m: p.verify(s, m), 44, 64, runs_count),
            ("ML-DSA-44", lambda: (lambda k: (k, k.public_key()))(mldsa.MLDSA44PrivateKey.generate()),
             lambda k, m: k.sign(m), lambda p, s, m: p.verify(s, m), 1334, 2420, runs_count),
            ("ML-DSA-65", lambda: (lambda k: (k, k.public_key()))(mldsa.MLDSA65PrivateKey.generate()),
             lambda k, m: k.sign(m), lambda p, s, m: p.verify(s, m), 1974, 3309, runs_count),
            ("ML-DSA-87", lambda: (lambda k: (k, k.public_key()))(mldsa.MLDSA87PrivateKey.generate()),
             lambda k, m: k.sign(m), lambda p, s, m: p.verify(s, m), 2614, 4627, runs_count),
        ]

        logs = [
            f"[{datetime.datetime.now().strftime('%H:%M:%S')}] BENCHMARK RUN #{run_id}",
            f"[*] Cau hinh: {runs_count} vong lap lay Median (+1 warm-up OpenSSL) | Payload: {len(bench_msg)} B",
        ]
        log_container.code("\n".join(logs), language="shell")

        bench_out = {}
        p_bar = progress_bar.progress(0)

        for idx, (name, kg_f, sg_f, vf_f, pk_s, sig_s, actual_runs) in enumerate(bench_targets):
            w_priv, w_pub = kg_f()
            w_out = sg_f(w_priv, bench_msg)
            vf_f(w_pub, w_out, bench_msg)

            kg_l, sg_l, vf_l = [], [], []
            for _ in range(actual_runs):
                t0 = time.perf_counter(); priv, pub = kg_f(); kg_l.append((time.perf_counter() - t0) * 1000)
                t0 = time.perf_counter(); s = sg_f(priv, bench_msg); sg_l.append((time.perf_counter() - t0) * 1000)
                t0 = time.perf_counter(); vf_f(pub, s, bench_msg); vf_l.append((time.perf_counter() - t0) * 1000)

            med_kg = statistics.median(kg_l)
            med_sg = statistics.median(sg_l)
            med_vf = statistics.median(vf_l)
            sg_ops = 1000.0 / med_sg if med_sg > 0 else 0
            vf_ops = 1000.0 / med_vf if med_vf > 0 else 0

            bench_out[name] = {
                "kg_ms": med_kg, "sg_ms": med_sg, "vf_ms": med_vf,
                "sg_ops": sg_ops, "vf_ops": vf_ops, "pk_bytes": pk_s, "sig_bytes": sig_s,
            }

            logs.append(
                f"[{datetime.datetime.now().strftime('%H:%M:%S')}] [{idx+1}/{len(bench_targets)}] {name:12s} ({actual_runs:2d} runs) "
                f"-> KeyGen: {med_kg:7.3f}ms | Sign: {med_sg:6.3f}ms | Verify: {med_vf:6.3f}ms ({sg_ops:7.0f} ops/s)"
            )
            log_container.code("\n".join(logs), language="shell")
            p_bar.progress((idx + 1) / len(bench_targets))

        logs.append(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] HOAN THANH DOT DO #{run_id}.")
        log_container.code("\n".join(logs), language="shell")
        progress_bar.empty()
        st.session_state["bench_logs"] = logs
        st.session_state["bench_results"] = bench_out

    elif st.session_state.get("bench_logs"):
        with st.expander(f"Nhật ký thực nghiệm — Đợt đo #{st.session_state.get('bench_run_count', 1)}"):
            st.code("\n".join(st.session_state["bench_logs"]), language="shell")

    if st.session_state["bench_results"]:
        b = st.session_state["bench_results"]
        run_id = st.session_state.get("bench_run_count", 1)
        ts = st.session_state.get("bench_timestamp", "Vừa xong")

        st.markdown(f"##### Kết quả đợt đo #{run_id} — `{ts}`")
        bench_rows = [
            {
                "Thuật toán": name,
                "KeyGen": f"{d['kg_ms']:.3f} ms",
                "Sign": f"{d['sg_ms']:.3f} ms",
                "Verify": f"{d['vf_ms']:.3f} ms",
                "Sign (ops/s)": f"{int(d['sg_ops']):,}",
                "Verify (ops/s)": f"{int(d['vf_ops']):,}",
                "Public Key (DER)": f"{d['pk_bytes']:,} B",
                "Signature": f"{d['sig_bytes']:,} B",
            }
            for name, d in b.items()
        ]
        st.dataframe(bench_rows, width="stretch", hide_index=True)

        col_g1, col_g2 = st.columns(2)
        names = list(b.keys())
        x = np.arange(len(names))
        w = 0.26

        with col_g1:
            fig1, ax1 = plt.subplots(figsize=(6.5, 4.1))
            ax1.bar(x - w, [b[n]["kg_ms"] for n in names], w, label="KeyGen", color=C_CYAN)
            ax1.bar(x, [b[n]["sg_ms"] for n in names], w, label="Sign", color=C_AMBER)
            ax1.bar(x + w, [b[n]["vf_ms"] for n in names], w, label="Verify", color=C_GREEN)
            ax1.set_yscale("log")
            ax1.set_ylabel("Thời gian CPU (ms — thang Log)")
            ax1.set_title(f"Độ trễ CPU: Chữ ký số Cổ điển vs ML-DSA (#{run_id})", fontsize=10, fontweight="bold")
            ax1.set_xticks(x)
            ax1.set_xticklabels(names, rotation=30, ha="right", fontsize=8)
            ax1.legend(fontsize=8, loc="upper right")
            _style_dark_fig(fig1, ax1)
            fig1.tight_layout()
            st.pyplot(fig1)
            plt.close(fig1)

        with col_g2:
            fig2, ax2 = plt.subplots(figsize=(6.5, 4.1))
            if chart_mode == "Thông lượng CPU (ops/s)":
                ax2.bar(x - 0.16, [b[n]["sg_ops"] for n in names], 0.32, label="Sign (ops/s)", color=C_BLUE)
                ax2.bar(x + 0.16, [b[n]["vf_ops"] for n in names], 0.32, label="Verify (ops/s)", color=C_TEAL)
                ax2.set_ylabel("Thông lượng (ops/giây — thang Log)")
                ax2.set_title(f"Thông lượng xử lý CPU (#{run_id})", fontsize=10, fontweight="bold")
                ax2.legend(fontsize=8, loc="upper right")
            else:
                ax2.bar(x - 0.18, [b[n]["pk_bytes"] for n in names], 0.36, label="Public Key (DER)", color=C_BLUE)
                ax2.bar(x + 0.18, [b[n]["sig_bytes"] for n in names], 0.36, label="Signature", color=C_RED)
                ax2.set_ylabel("Kích thước (Bytes — thang Log)")
                ax2.set_title("Kích thước Khóa & Chữ ký (Chuẩn NIST)", fontsize=10, fontweight="bold")
                ax2.legend(fontsize=8, loc="upper left")
            ax2.set_yscale("log")
            ax2.set_xticks(x)
            ax2.set_xticklabels(names, rotation=30, ha="right", fontsize=8)
            _style_dark_fig(fig2, ax2)
            fig2.tight_layout()
            st.pyplot(fig2)
            plt.close(fig2)

        rsa_kg = b.get("RSA-2048", {}).get("kg_ms", 40.0)
        mldsa_kg = b.get("ML-DSA-65", {}).get("kg_ms", 0.4)
        ratio_rsa = rsa_kg / mldsa_kg if mldsa_kg > 0 else 0
        mldsa_sg = b.get("ML-DSA-65", {}).get("sg_ms", 0.5)
        mldsa_vf = b.get("ML-DSA-65", {}).get("vf_ms", 0.2)
        rsa_sg = b.get("RSA-2048", {}).get("sg_ms", 1.0)
        st.info(
            f"**Nhận xét thực nghiệm (Đợt #{run_id}):**\n"
            f"- **ML-DSA-65 vs RSA-2048:** KeyGen ML-DSA-65 nhanh hơn **{ratio_rsa:.1f} lần** ({rsa_kg:.2f} ms vs {mldsa_kg:.3f} ms); "
            f"tốc độ ký ({mldsa_sg:.3f} ms vs {rsa_sg:.3f} ms) ở cùng ngưỡng mili-giây.\n"
            f"- **Xác minh (Verify) ML-DSA-65:** Đạt **{mldsa_vf:.3f} ms** (~**{int(1000.0 / mldsa_vf) if mldsa_vf > 0 else 0:,} ops/s** trên 1 nhân), "
            "cho thấy chi phí xử lý CPU ở mức thấp, trong khi kích thước khóa và chữ ký (3,309 B) mới là yếu tố đánh đổi chính."
        )

        col_exp1, col_exp2 = st.columns(2)
        with col_exp1:
            with st.expander("Sao chép bảng Markdown cho báo cáo Chapter 3"):
                md_table = "| Thuật toán | KeyGen | Sign | Verify | Sign (ops/s) | Verify (ops/s) |\n"
                md_table += "|:---|:---:|:---:|:---:|:---:|:---:|\n"
                for r in bench_rows:
                    md_table += f"| **{r['Thuật toán']}** | {r['KeyGen']} | {r['Sign']} | {r['Verify']} | {r['Sign (ops/s)']} | {r['Verify (ops/s)']} |\n"
                st.code(md_table, language="markdown")

        with col_exp2:
            csv_buf = io.StringIO()
            csv_buf.write("Algorithm,KeyGen_ms,Sign_ms,Verify_ms,Sign_ops_sec,Verify_ops_sec,PublicKey_DER_bytes,Signature_bytes\n")
            for name, d in b.items():
                csv_buf.write(f"{name},{d['kg_ms']:.4f},{d['sg_ms']:.4f},{d['vf_ms']:.4f},{d['sg_ops']:.2f},{d['vf_ops']:.2f},{d['pk_bytes']},{d['sig_bytes']}\n")
            st.download_button(
                label=f"Tải tệp CSV kết quả đợt #{run_id}",
                data=csv_buf.getvalue(),
                file_name=f"benchmark_results_run_{run_id}.csv",
                mime="text/csv",
                width="stretch",
            )
    else:
        st.caption("Bấm **Chạy đo hiệu năng CPU** để đo trực tiếp trên máy hiện tại.")

# ==============================================================================
# TAB 4: 3-TIER X.509 PKI CHAIN & TLS 1.3 NETWORK IMPACT
# ==============================================================================
with tab4:
    st.markdown("#### Chuỗi chứng chỉ X.509 3 cấp & Tác động bắt tay TLS 1.3")
    st.caption("Mô phỏng PKI 3 cấp: Root CA -> Intermediate CA -> Leaf Server Certificate (RFC 9881) đối chiếu với cửa sổ TCP ban đầu (14.6 KB).")

    if st.button("Dựng chuỗi X.509 & đo kích thước TLS 1.3", type="primary", width="stretch"):
        pki_specs = [
            ("RSA-2048", lambda: rsa.generate_private_key(65537, 2048), hashes.SHA256(), 256),
            ("ECDSA P-256", lambda: ec.generate_private_key(ec.SECP256R1()), hashes.SHA256(), 71),
            ("ML-DSA-44", lambda: mldsa.MLDSA44PrivateKey.generate(), None, 2420),
            ("ML-DSA-65", lambda: mldsa.MLDSA65PrivateKey.generate(), None, 3309),
            ("ML-DSA-87", lambda: mldsa.MLDSA87PrivateKey.generate(), None, 4627),
        ]

        pki_out = {}
        now = datetime.datetime.now(datetime.timezone.utc)

        for name, gen_fn, hash_algo, sig_overhead in pki_specs:
            root_k = gen_fn()
            root_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{name} Root CA")])
            root_cert = (
                x509.CertificateBuilder()
                .subject_name(root_subj).issuer_name(root_subj)
                .public_key(root_k.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650))
                .sign(root_k, hash_algo)
            )

            inter_k = gen_fn()
            inter_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{name} Inter CA")])
            inter_cert = (
                x509.CertificateBuilder()
                .subject_name(inter_subj).issuer_name(root_subj)
                .public_key(inter_k.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1825))
                .sign(root_k, hash_algo)
            )

            leaf_k = gen_fn()
            leaf_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "server.network-sec.local")])
            leaf_cert = (
                x509.CertificateBuilder()
                .subject_name(leaf_subj).issuer_name(inter_subj)
                .public_key(leaf_k.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=365))
                .sign(inter_k, hash_algo)
            )

            root_der = root_cert.public_bytes(serialization.Encoding.DER)
            inter_der = inter_cert.public_bytes(serialization.Encoding.DER)
            leaf_der = leaf_cert.public_bytes(serialization.Encoding.DER)

            chain_sent = len(inter_der) + len(leaf_der)
            tls_auth_bytes = chain_sent + sig_overhead
            pki_out[name] = {
                "root_b": len(root_der),
                "inter_b": len(inter_der),
                "leaf_b": len(leaf_der),
                "chain_b": chain_sent,
                "auth_b": tls_auth_bytes,
                "cwnd_pct": (tls_auth_bytes / 14600.0) * 100.0,
                "mtu_pkts": int(np.ceil(tls_auth_bytes / 1460)),
            }

        st.session_state["pki_results"] = pki_out
        st.success("Hoàn tất dựng chuỗi chứng chỉ X.509 3 cấp.")

    if st.session_state["pki_results"]:
        p = st.session_state["pki_results"]
        pki_table = [
            {
                "Thuật toán": name,
                "Root CA (DER)": f"{d['root_b']:,} B",
                "Inter CA (DER)": f"{d['inter_b']:,} B",
                "Leaf Cert (DER)": f"{d['leaf_b']:,} B",
                "Chuỗi gửi (Inter + Leaf)": f"{d['chain_b']:,} B",
                "Tổng TLS Auth": f"{d['auth_b']:,} B",
                "% initcwnd (14.6 KB)": f"{d['cwnd_pct']:.1f}%",
                "Số gói TCP": f"{d['mtu_pkts']} gói",
            }
            for name, d in p.items()
        ]
        st.dataframe(pki_table, width="stretch", hide_index=True)

        pki_names = list(p.keys())
        auth_vals = [p[n]["auth_b"] for n in pki_names]

        fig_tls, ax_tls = plt.subplots(figsize=(8.2, 3.8))
        colors = [C_GREEN if val <= 14600 else C_RED for val in auth_vals]
        bars = ax_tls.bar(pki_names, auth_vals, color=colors, width=0.48)
        ax_tls.axhline(14600, color=C_AMBER, linestyle="--", linewidth=1.5, label="Initial TCP Window (10 MSS = 14.6 KB)")
        for bar in bars:
            h = bar.get_height()
            ax_tls.annotate(
                f"{h:,} B",
                xy=(bar.get_x() + bar.get_width() / 2, h),
                xytext=(0, 4),
                textcoords="offset points",
                ha="center",
                fontsize=8.5,
                fontweight="bold",
                color="#F1F5F9",
            )
        ax_tls.set_ylabel("Dữ liệu xác thực TLS 1.3 (Bytes)")
        ax_tls.set_title("Tác động dữ liệu xác thực TLS 1.3 lên cửa sổ TCP khởi tạo", fontsize=10, fontweight="bold")
        ax_tls.legend(loc="upper left", fontsize=8.5)
        _style_dark_fig(fig_tls, ax_tls)
        fig_tls.tight_layout()
        st.pyplot(fig_tls)
        plt.close(fig_tls)

        ec_d = p["ECDSA P-256"]
        rsa_d = p["RSA-2048"]
        m44_d = p["ML-DSA-44"]
        m65_d = p["ML-DSA-65"]
        m87_d = p["ML-DSA-87"]
        m65_margin = 14600 - m65_d["auth_b"]
        m87_over = m87_d["auth_b"] - 14600

        st.markdown("##### Giải thích kết quả mô phỏng & điểm nghẽn mạng TLS 1.3")
        st.info(
            "**1. Web vừa thực hiện gì?**\n"
            "Dựng thật chuỗi chứng chỉ số HTTPS 3 cấp (`Root CA → Intermediate CA → Leaf Server`) cho cả 5 thuật toán "
            "(Root CA đã có sẵn trong máy Client nên Server không gửi qua mạng), sau đó tính tổng dữ liệu xác thực Server phải gửi khi bắt tay TLS 1.3:\n\n"
            "$$\\text{Tổng TLS Auth} = \\text{Intermediate Cert} + \\text{Leaf Cert} + \\text{Chữ ký CertificateVerify}$$\n\n"
            "Vạch đứt ngang **14,600 B (14.6 KB)** là **cửa sổ TCP khởi đầu (`initcwnd = 10` gói TCP × `1,460 B` MSS)** — "
            "lượng dữ liệu tối đa Server được phát đi trong lượt đầu tiên mà chưa cần dừng chờ Client phản hồi `ACK`."
        )
        st.warning(
            "**2. Phân tích điểm nghẽn truyền tải trên mạng:**\n\n"
            "Mặc dù thời gian xử lý CPU thấp, **kích thước gói tin và băng thông mạng mới là hạn chế chính của ML-DSA** (đo trực tiếp từ đợt dựng chuỗi vừa chạy):\n"
            f"- **ECDSA P-256:** tốn **{ec_d['auth_b']:,} B** (**{ec_d['mtu_pkts']} gói TCP**, `{ec_d['cwnd_pct']:.1f}%` cửa sổ) — kích thước rất nhỏ.\n"
            f"- **RSA-2048:** tốn **{rsa_d['auth_b']:,} B** (**{rsa_d['mtu_pkts']} gói TCP**, `{rsa_d['cwnd_pct']:.1f}%` cửa sổ).\n"
            f"- **ML-DSA-44:** tăng lên **{m44_d['auth_b']:,} B** (**{m44_d['mtu_pkts']} gói TCP**, `{m44_d['cwnd_pct']:.1f}%` cửa sổ) — vẫn nằm trọn trong lượt gửi đầu tiên.\n"
            f"- **ML-DSA-65:** đạt **{m65_d['auth_b']:,} B** (**{m65_d['mtu_pkts']} gói TCP**, `{m65_d['cwnd_pct']:.1f}%` cửa sổ) — "
            f"tiệm cận ngưỡng 14.6 KB (phần dư **{m65_margin:,} B**, dễ vượt ngưỡng nếu kèm thêm phần mở rộng chứng chỉ hoặc ML-KEM).\n"
            f"- **ML-DSA-87:** tăng lên **{m87_d['auth_b']:,} B** (**{m87_d['mtu_pkts']} gói TCP**, `{m87_d['cwnd_pct']:.1f}%` cửa sổ) — "
            f"**vượt ngưỡng 14.6 KB thêm {m87_over:,} B**, làm kết nối TLS 1.3 phát sinh thêm **1 vòng truyền nhận (+1 RTT)** mới hoàn tất bắt tay."
        )

# ==============================================================================
# TAB 5: MESSAGE LENGTH SCALABILITY (32 B -> 1 MiB)
# ==============================================================================
with tab5:
    st.markdown("#### Khảo sát độ co giãn theo chiều dài thông điệp (32 B → 1 MiB)")
    st.caption("Kiểm chứng cơ chế băm nội bộ SHAKE-256 (NIST FIPS 204) giúp thời gian ký ML-DSA ổn định khi kích thước tệp tăng mạnh.")

    if st.button("Đo độ co giãn (32 Bytes đến 1 MiB)", type="primary", width="stretch"):
        msg_sizes = [
            ("32 B", 32),
            ("1 KiB", 1024),
            ("16 KiB", 16 * 1024),
            ("256 KiB", 256 * 1024),
            ("1 MiB", 1024 * 1024),
        ]

        k_rsa = rsa.generate_private_key(65537, 2048)
        k_ec = ec.generate_private_key(ec.SECP256R1())
        k_ed = ed25519.Ed25519PrivateKey.generate()
        k_mldsa = mldsa.MLDSA65PrivateKey.generate()

        scale_res = {"RSA-2048": [], "ECDSA P-256": [], "Ed25519": [], "ML-DSA-65": []}
        for _, sz in msg_sizes:
            data = os.urandom(sz)
            t0 = time.perf_counter()
            for _ in range(5):
                k_rsa.sign(data, padding.PKCS1v15(), hashes.SHA256())
            scale_res["RSA-2048"].append((time.perf_counter() - t0) / 5 * 1000)

            t0 = time.perf_counter()
            for _ in range(10):
                k_ec.sign(data, ec.ECDSA(hashes.SHA256()))
            scale_res["ECDSA P-256"].append((time.perf_counter() - t0) / 10 * 1000)

            t0 = time.perf_counter()
            for _ in range(10):
                k_ed.sign(data)
            scale_res["Ed25519"].append((time.perf_counter() - t0) / 10 * 1000)

            t0 = time.perf_counter()
            for _ in range(10):
                k_mldsa.sign(data)
            scale_res["ML-DSA-65"].append((time.perf_counter() - t0) / 10 * 1000)

        st.session_state["msg_scalability"] = {"sizes": [l for l, _ in msg_sizes], "res": scale_res}
        st.success("Hoàn thành đo đạc độ co giãn.")

    if st.session_state["msg_scalability"]:
        sc = st.session_state["msg_scalability"]
        labels = sc["sizes"]
        res = sc["res"]

        scale_table = [
            {"Thuật toán": algo, **{l: f"{t:.3f} ms" for l, t in zip(labels, times)}}
            for algo, times in res.items()
        ]
        st.dataframe(scale_table, width="stretch", hide_index=True)

        palette = [C_SLATE, C_CYAN, C_GREEN, C_BLUE]
        fig_sc, ax_sc = plt.subplots(figsize=(8.2, 3.9))
        for (algo, times), col in zip(res.items(), palette):
            lw = 2.4 if algo == "ML-DSA-65" else 1.7
            ls = "-" if algo == "ML-DSA-65" else "--"
            ax_sc.plot(labels, times, marker="o", linewidth=lw, linestyle=ls, color=col, label=algo)
        ax_sc.set_ylabel("Thời gian ký (ms)")
        ax_sc.set_title("Độ nhạy thời gian ký khi dữ liệu tăng từ 32 B đến 1 MiB", fontsize=10.5, fontweight="bold")
        ax_sc.legend(fontsize=8.5)
        _style_dark_fig(fig_sc, ax_sc)
        fig_sc.tight_layout()
        st.pyplot(fig_sc)
        plt.close(fig_sc)

        st.info(
            "**Kết luận:** ML-DSA băm toàn bộ thông điệp qua SHAKE-256 trước khi vào vòng lặp "
            "Rejection Sampling trong $R_q$, do đó thời gian ký hầu như ổn định khi tệp tăng đến 1 MiB."
        )
