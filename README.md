# Penjelas Dokumen

Website Penjelas Dokumen dengan akun pengguna, penyimpanan dokumen/riwayat di SQLite, pembacaan PDF, TXT, foto, dan PDF scan, rangkuman, penandaan bagian penting, tanya jawab, serta koneksi WhatsApp.

## Menjalankan di Mac ini

```bash
cd "/Users/acun/Documents/Tugas teknik pemograman/project UAS/Penjelas Dokumen"
PYTHONPYCACHEPREFIX=/private/tmp/penjelas-pycache PYTHONPATH="$PWD/.venv/lib/python3.9/site-packages" PORT=5001 /usr/bin/python3 app.py
```

Buka http://127.0.0.1:5001. Buat akun dari tombol **Mulai gratis** atau menu **Daftar**. Password minimal 8 karakter. Akun disimpan di SQLite dan password tidak disimpan sebagai teks biasa.

## Yang sudah terhubung

- Daftar akun, login, dan logout melalui backend Flask.
- Email unik dan validasi password.
- Password disimpan sebagai hash.
- Session cookie HttpOnly dan token CSRF untuk permintaan perubahan data.
- Dokumen PDF, TXT, foto, dan PDF scan dibaca lalu teksnya disimpan di SQLite sesuai akun.
- Pengguna mendapat kode pemulihan untuk mereset password sendiri, dan login dibatasi setelah 10 percobaan gagal.
- Daftar dokumen dan riwayat percakapan disimpan di server, bukan hanya browser.
- Analisis dasar dan jawaban pertanyaan memakai aturan lokal serta kutipan dari dokumen.
- Owner dapat mengaktifkan analisis AI Groq dari dashboard. Setiap pengguna diminta menyetujui pengiriman dokumennya sebelum teks dikirim untuk analisis.
- Dashboard owner menampilkan akun, dokumen, dan riwayat chat, serta dapat menghapus dokumen atau akun pengguna.
- Owner dapat membuat password sementara baru untuk akun pengguna; password yang sudah ada tidak pernah ditampilkan.
- Pengguna yang masuk dapat mengganti password sendiri dengan memverifikasi password saat ini dan mengonfirmasi password baru.
- Pilihan paket Gratis, Personal, dan Pro ditampilkan sebelum daftar dan dapat diganti dari menu **Paket saya**. Langganan/pembayaran masih simulasi.
- Akun `a.tanata@yahoo.com` otomatis diberi akses owner. Alamat ini dapat diganti lewat variabel `OWNER_EMAIL` sebelum server dijalankan.

## Batasan versi ini

Jalankan `pip install -r requirements.txt` agar semua pembaca dokumen tersedia. Foto dan PDF scan dibaca model vision Groq (`GROQ_VISION_MODEL`, bawaan `qwen/qwen3.8-27b`, masih berstatus preview di Groq) kalau pengguna setuju, atau Tesseract di server kalau pengguna menolak atau Groq gagal, maksimal 8 halaman per PDF. Langganan masih simulasi.

Kunci API tersimpan lokal di folder `instance/` yang tidak diunggah ke Git, atau lewat variabel `GROQ_API_KEY`.

## Verifikasi email

Aktif kalau `BREVO_API_KEY` dan `EMAIL_FROM` (pengirim yang sudah diverifikasi di Brevo) diisi. Isi juga `PUBLIC_URL`, misalnya `https://pikacun.pythonanywhere.com`. Akun lama tetap dianggap terverifikasi. Tanpa pengaturan ini, pendaftaran langsung aktif seperti sebelumnya.

## Menghubungkan WhatsApp

Fitur ini memakai WhatsApp Cloud API resmi dan baru aktif setelah semua variabel ini diisi. Tanpa itu, tab WhatsApp hanya memberi tahu bahwa fitur belum aktif.

| Variabel | Isi |
| --- | --- |
| `WHATSAPP_TOKEN` | Access token permanen dari system user Meta |
| `WHATSAPP_PHONE_NUMBER_ID` | Phone number ID di Meta |
| `WHATSAPP_NUMBER` | Nomor WhatsApp bisnis dengan kode negara, misalnya `628123456789` |
| `WHATSAPP_APP_SECRET` | App secret aplikasi Meta |
| `WHATSAPP_VERIFY_TOKEN` | Teks acak buatan sendiri |

Di dashboard Meta, atur webhook ke `https://DOMAIN-KAMU/webhook/whatsapp` dengan verify token yang sama, lalu langganan field `messages`.

## Test

```bash
PYTHONPATH="$PWD/.venv/lib/python3.9/site-packages" /usr/bin/python3 -m unittest discover -s tests -v
```

Test memakai database sementara dan tiruan Groq serta WhatsApp, jadi tidak menyentuh data asli maupun internet.

## Lupa password (owner lokal)

Jalankan perintah ini dari folder proyek:

```bash
PYTHONPYCACHEPREFIX=/private/tmp/penjelas-pycache PYTHONPATH="$PWD/.venv/lib/python3.9/site-packages" /usr/bin/python3 app.py --reset-password
```

Masukkan email akun, lalu masukkan password baru dua kali. Password tidak akan tampil saat diketik dan hanya pemilik Mac yang menjalankan perintah ini dapat mereset akun.
