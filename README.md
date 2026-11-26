# Hệ Thống Mô Phỏng & Đo Đạc Thực Nghiệm ML-DSA vs ML-KEM (NIST FIPS 204 / FIPS 203)

Ứng dụng web tương tác bằng **Streamlit** dùng để mô phỏng mật mã thật 100%, trực quan hóa bản chất toán học **Module-Lattice**, kịch bản tấn công **MITM kênh lai `ML-KEM + ML-DSA`** và đo đạc hiệu năng CPU đối chiếu với các chuẩn cổ điển (**RSA, ECDSA, Ed25519**).

## Cấu trúc thư mục

```text
pqc_simulation/
├── .streamlit/
│   └── config.toml           # Cấu hình cổng 8888 & giao diện nền tối
├── app_pqc_simulation.py     # Mã nguồn duy nhất (tích hợp trọn vẹn lõi mật mã & 5 tabs)
├── requirements.txt          # Danh sách thư viện Python cần thiết
└── README.md                 # Tài liệu hướng dẫn cài đặt & demo
```

## 5 Mô-đun chức năng chính

1. **Tab 1 — Mô Phỏng Sinh Khóa FIPS 204 (Algorithm 6):** Sơ đồ 4 bước trực quan (`Seed ξ 32B → SHAKE-256 → A, s₁, s₂ → t = A·s₁ + s₂ → PK/SK`), thanh tỉ lệ bộ nhớ màu (khớp từng bit với OpenSSL 3.5) và 1 bảng kích thước duy nhất (Cổ điển vs `ML-KEM` vs `ML-DSA`).
2. **Tab 2 — ML-DSA vs ML-KEM & Kính Hiển Vi Module-Lattice (Trọng tâm):**
   - **2A. Kịch bản MITM 3 chế độ (`Chỉ ML-KEM + AES` | `Chỉ ML-DSA` | `Đủ cả hai`):**
     - **Chỉ `ML-KEM + AES` (thiếu `ML-DSA`):** Hacker tráo `pk_KEM_Server` bằng `pk_KEM_Hacker`, **vừa đọc 100% bản rõ vừa sửa lệnh** sang Server.
     - **Chỉ `ML-DSA` (thiếu `ML-KEM + AES`):** `ML-DSA` **chặn đứng hành vi sửa/tráo**, nhưng Hacker vẫn **nghe lén đọc 100% bản rõ** vì không mã hóa.
     - **Đủ cả hai (`ML-KEM + AES + ML-DSA`):** Chặn tráo khóa ngay tại bước bắt tay (`Hacker thu 0 bytes`) và bảo mật toàn bộ kênh truyền.
   - **2B. Kính Hiển Vi Module-Lattice White-Box (`dilithium_py` chuẩn FIPS 204):**
     - Mổ xẻ thật Algorithm 7 (Sign): nhật ký từng vòng lặp **Rejection Sampling (`kappa`)** cùng giá trị thực tế $\|z\|_\infty$, $\|r_0\|_\infty$, $\|c\cdot t_0\|_\infty$, `sum(h)` và lý do `ABORT / ACCEPT`, đồng thời đối chiếu chéo chữ ký sinh ra với OpenSSL 3.5 gốc.
     - Mổ xẻ thật Algorithm 8 (Verify): kiểm chứng đẳng thức mạng lưới $w'_1 = \text{UseHint}(h, A z - c t_1 \cdot 2^d \bmod q)$ khi lật bit có chủ đích vào từng vùng $\tilde{c}$, $z$, hoặc $h$.
     - **Thí nghiệm Bật vs Tắt Rejection Sampling:** Vẽ phân phối vùng biên $|z|$ và histogram số vòng lặp `attempts`, chứng minh tắt Rejection Sampling gây tràn biên $\pm(\gamma_1 - \beta)$ làm rò rỉ dấu khóa bí mật $s_1$, đồng thời lý giải vì sao ML-DSA chậm & biến thiên hơn ML-KEM (chạy đúng 1 lượt).
3. **Tab 3 — Đo Đạc Hiệu Năng CPU:** Đo trung vị thời gian `KeyGen`, `Sign/Encap`, `Verify/Decap` (kèm vòng warm-up OpenSSL) trên cả **RSA, ECDSA, Ed25519, ML-KEM-768/1024 và ML-DSA-44/65/87**, tự động so sánh tỷ lệ `ML-DSA-65 vs ML-KEM-768` và xuất bảng Markdown/CSV.
4. **Tab 4 — Chuỗi PKI X.509 & TLS 1.3:** Dựng chuỗi chứng chỉ 3 cấp (`Root CA → Intermediate CA → Leaf`) và đánh giá tải truyền so với cửa sổ TCP khởi đầu (`initcwnd ≈ 14.6 KB`).
5. **Tab 5 — Độ Co Giãn Kích Thước Tệp:** Kiểm thử tính ổn định thời gian ký từ `32 B` đến `1 MiB` nhờ cơ chế băm nội bộ SHAKE-256.

## Yêu cầu môi trường

- **Python:** `3.11+` (đã kiểm chứng trên `Python 3.13.7`)
- **Thư viện lõi:** `cryptography >= 50.0.2` (OpenSSL 3.5+ native `mldsa` và `mlkem`), `dilithium-py >= 1.5.1` (FIPS 204 thuần Python cho White-Box), `streamlit`, `matplotlib`, `numpy`, `pandas`.
- *Lưu ý về `ML-KEM-512`:* `cryptography 50.0.2` cung cấp binding native cho `ML-KEM-768` và `ML-KEM-1024`; thông số chuẩn của `ML-KEM-512` (FIPS 203 Cấp 1) được đối chiếu đầy đủ trong bảng lý thuyết của Tab 2A (và đo trực tiếp qua OpenSSL 3.5 CLI trong Notebook `pqc_benchmarks/PQC_Comprehensive_Comparison.ipynb`).

## Hướng dẫn cài đặt & Chạy nhanh

### 1. Tạo môi trường ảo và cài đặt thư viện

**Windows (PowerShell):**
```powershell
cd pqc_simulation
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**macOS / Linux:**
```bash
cd pqc_simulation
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Khởi chạy ứng dụng web

Chạy trực tiếp bằng Python (tự động mở trình duyệt tại `http://localhost:8888`):
```bash
python app_pqc_simulation.py
```

Hoặc chạy qua lệnh Streamlit chuẩn:
```bash
streamlit run app_pqc_simulation.py --server.port 8888
```

## Kịch bản Demo nhanh khi bảo vệ (3 phút)

1. **Tab 1 (`1. Sinh khóa`):** Bấm `Sinh cặp khóa mới` để trình bày sơ đồ 4 bước Algorithm 6 (`Seed ξ 32B → Ma trận A & bí mật s₁, s₂ → t = A·s₁ + s₂ → PK/SK`) và 2 thanh cấu trúc bộ nhớ màu (khớp từng bit với OpenSSL 3.5).
2. **Tab 2A (`2. ML-DSA & ML-KEM`):** Chọn kịch bản MB Bank 24/7 (`A → B`), bấm lần lượt 3 chế độ bảo vệ: (1) `Chỉ ML-KEM + AES`: Hacker tráo khóa vừa đọc vừa sửa 100%; (2) `Chỉ ML-DSA`: Hacker không sửa được nhưng đọc lén hết bản rõ; (3) `Đủ cả hai`: Chặn đứng Hacker ngay ở Bước 3 (< 1 ms), Hacker thu `0 bytes`.
3. **Tab 2B (`Cấu trúc Module-Lattice`):** Xem sơ đồ 4 bước và chuỗi vòng lặp `ABORT → ACCEPT` thật, sau đó bấm `Chạy thí nghiệm Rejection Sampling` để chỉ biểu đồ cắt biên $|z| < \gamma_1 - \beta$ và lý do ML-DSA chậm hơn ML-KEM.
4. **Tab 3 (`3. Hiệu năng CPU`):** Bấm `Chạy đo hiệu năng CPU` để đối chứng trực tiếp số liệu thật giữa `ML-DSA-65` và `ML-KEM-768`.
