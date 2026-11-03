# Penjelas Dokumen

Website Penjelas Dokumen dengan akun pengguna, penyimpanan dokumen/riwayat di SQLite, ekstraksi teks PDF, rangkuman, penandaan bagian penting, dan tanya jawab berbasis aturan lokal.

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
- Dokumen PDF berbasis teks dan TXT dibaca lalu disimpan di SQLite sesuai akun.
- Daftar dokumen dan riwayat percakapan disimpan di server, bukan hanya browser.
- Analisis dasar dan jawaban pertanyaan memakai aturan lokal serta kutipan dari dokumen.
- Owner dapat mengaktifkan analisis AI Groq dari dashboard. Setiap pengguna diminta menyetujui pengiriman dokumennya sebelum teks dikirim untuk analisis.
- Dashboard owner menampilkan akun, dokumen, dan riwayat chat, serta dapat menghapus dokumen atau akun pengguna.
- Owner dapat membuat password sementara baru untuk akun pengguna; password yang sudah ada tidak pernah ditampilkan.
- Pengguna yang masuk dapat mengganti password sendiri dengan memverifikasi password saat ini dan mengonfirmasi password baru.
- Pilihan paket Gratis, Personal, dan Pro ditampilkan sebelum daftar dan dapat diganti dari menu **Paket saya**. Langganan/pembayaran masih simulasi.
- Akun `a.tanata@yahoo.com` otomatis diberi akses owner. Alamat ini dapat diganti lewat variabel `OWNER_EMAIL` sebelum server dijalankan.

## Batasan versi ini

Jalankan `pip install -r requirements.txt` agar pembaca PDF tersedia. PDF hasil scan dan foto belum bisa dibaca karena OCR belum dipasang. AI membutuhkan Groq API key milik owner; teks dokumen hanya dikirim ke layanan itu setelah pengguna menyetujui konfirmasi di halaman analisis. Kunci API tersimpan lokal di folder `instance/` yang tidak diunggah ke Git. Bagian WhatsApp hanya pratinjau QR dan belum tersambung. Dokumen disimpan lokal di `instance/app.db` pada Mac ini.


## Lupa password (owner lokal)

Jalankan perintah ini dari folder proyek:

```bash
PYTHONPYCACHEPREFIX=/private/tmp/penjelas-pycache PYTHONPATH="$PWD/.venv/lib/python3.9/site-packages" /usr/bin/python3 app.py --reset-password
```

Masukkan email akun, lalu masukkan password baru dua kali. Password tidak akan tampil saat diketik dan hanya pemilik Mac yang menjalankan perintah ini dapat mereset akun.
