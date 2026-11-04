"""Test otomatis. Jalankan dari folder project: python -m unittest discover -s tests -v

Tidak ada permintaan yang keluar ke internet: Groq dan WhatsApp diganti tiruan.
"""
import hashlib
import hmac
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TEMP = tempfile.TemporaryDirectory()
os.environ["DATABASE_PATH"] = str(Path(TEMP.name) / "test.db")
os.environ["SECRET_KEY"] = "kunci-khusus-test"
os.environ["OWNER_EMAIL"] = "owner@test.test"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as web  # noqa: E402

LONG_TEXT = "Pasal 1: Sewa sebesar Rp2.000.000 per bulan. Pasal 2: Denda keterlambatan 2% per hari dari nilai sewa."
WA_ENV = {"WHATSAPP_TOKEN": "t", "WHATSAPP_PHONE_NUMBER_ID": "123", "WHATSAPP_VERIFY_TOKEN": "cocok",
          "WHATSAPP_APP_SECRET": "rahasia", "WHATSAPP_NUMBER": "+62 811-000"}


class Base(unittest.TestCase):
    counter = 0

    def setUp(self):
        Base.counter += 1
        self.email = "user%d@test.test" % Base.counter
        self.client = web.app.test_client()
        self.csrf = self.client.get("/api/me").get_json()["csrf"]
        patcher = mock.patch.object(web.urllib.request, "urlopen", side_effect=AssertionError("tidak boleh ke internet"))
        patcher.start()
        self.addCleanup(patcher.stop)
        key = mock.patch.object(web, "groq_api_key", return_value="")
        self.key = key.start()
        self.addCleanup(key.stop)

    def post(self, path, payload=None, client=None, csrf=None):
        return (client or self.client).post(path, json=payload or {}, headers={"X-CSRF-Token": csrf or self.csrf})

    def register(self):
        response = self.post("/api/register", {"email": self.email, "password": "password-uji-1"})
        self.assertEqual(response.status_code, 201)
        data = response.get_json()
        self.csrf = data["csrf"]
        return data

    def upload(self, name, raw, mode=None):
        data = {"file": (io.BytesIO(raw), name)}
        if mode:
            data["ocr"] = mode
        return self.client.post("/api/extract", data=data, headers={"X-CSRF-Token": self.csrf}, content_type="multipart/form-data")


class SecurityTests(Base):
    def test_security_headers(self):
        headers = self.client.get("/").headers
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])

    def test_csrf_required(self):
        response = self.client.post("/api/login", json={"email": "a@b.co", "password": "x"})
        self.assertEqual(response.status_code, 400)

    def test_login_locks_after_repeated_failures(self):
        self.register()
        fresh = web.app.test_client()
        token = fresh.get("/api/me").get_json()["csrf"]
        for _ in range(web.LOGIN_MAX_FAILURES):
            self.assertEqual(self.post("/api/login", {"email": self.email, "password": "salah-terus"}, fresh, token).status_code, 401)
        response = self.post("/api/login", {"email": self.email, "password": "password-uji-1"}, fresh, token)
        self.assertEqual(response.status_code, 429)

    def test_documents_are_private_per_user(self):
        self.register()
        doc = self.post("/api/documents", {"name": "a.txt", "text": LONG_TEXT}).get_json()
        other = web.app.test_client()
        token = other.get("/api/me").get_json()["csrf"]
        token = self.post("/api/register", {"email": "lain" + self.email, "password": "password-uji-2"}, other, token).get_json()["csrf"]
        response = other.delete("/api/documents/%d" % doc["id"], headers={"X-CSRF-Token": token})
        self.assertEqual(other.get("/api/workspace").get_json()["documents"], [])
        self.assertIn(doc["id"], [d["id"] for d in self.client.get("/api/workspace").get_json()["documents"]], response.status_code)

    def test_large_request_rejected(self):
        self.register()
        response = self.upload("besar.txt", b"a" * (web.app.config["MAX_CONTENT_LENGTH"] + 10))
        self.assertEqual(response.status_code, 413)


class RecoveryTests(Base):
    def test_recovery_code_resets_password_once(self):
        code = self.register()["recovery_code"]
        fresh = web.app.test_client()
        token = fresh.get("/api/me").get_json()["csrf"]
        wrong = self.post("/api/recover", {"email": self.email, "code": "SALAH", "new_password": "password-baru-1"}, fresh, token)
        self.assertEqual(wrong.status_code, 401)
        done = self.post("/api/recover", {"email": self.email, "code": code.lower(), "new_password": "password-baru-1"}, fresh, token)
        self.assertEqual(done.status_code, 200)
        self.assertNotEqual(done.get_json()["recovery_code"], code)
        other = web.app.test_client()
        token = other.get("/api/me").get_json()["csrf"]
        again = self.post("/api/recover", {"email": self.email, "code": code, "new_password": "password-baru-2"}, other, token)
        self.assertEqual(again.status_code, 401)
        self.assertEqual(self.post("/api/login", {"email": self.email, "password": "password-baru-1"}, other, token).status_code, 200)


class ExtractTests(Base):
    def picture(self):
        from PIL import Image
        buffer = io.BytesIO()
        Image.new("RGB", (60, 40), "white").save(buffer, "PNG")
        return buffer.getvalue()

    def blank_pdf(self):
        from pypdf import PdfWriter
        writer, buffer = PdfWriter(), io.BytesIO()
        writer.add_blank_page(width=200, height=200)
        writer.write(buffer)
        return buffer.getvalue()

    def test_txt(self):
        self.register()
        self.assertEqual(self.upload("a.txt", LONG_TEXT.encode()).get_json()["text"], LONG_TEXT)

    def test_photo_without_any_reader_explains(self):
        self.register()
        with mock.patch.object(web, "local_ocr_text", side_effect=OSError("tidak ada")):
            self.assertEqual(self.upload("a.png", self.picture()).status_code, 503)

    def test_photo_without_ai_key_uses_server_reader(self):
        self.register()
        with mock.patch.object(web, "local_ocr_text", return_value=LONG_TEXT), mock.patch.object(web, "groq_completion") as groq:
            self.assertEqual(self.upload("a.png", self.picture()).get_json()["text"], LONG_TEXT)
        groq.assert_not_called()

    def test_declining_ai_never_contacts_groq(self):
        self.register()
        self.key.return_value = "kunci"
        with mock.patch.object(web, "local_ocr_text", return_value=LONG_TEXT), mock.patch.object(web, "groq_completion") as groq:
            self.assertEqual(self.upload("a.png", self.picture(), mode="local").status_code, 200)
        groq.assert_not_called()

    def test_blocked_ai_falls_back_to_server_reader(self):
        self.register()
        self.key.return_value = "kunci"
        with mock.patch.object(web, "groq_completion", side_effect=RuntimeError("Akses Groq ditolak.")), mock.patch.object(web, "local_ocr_text", return_value=LONG_TEXT):
            self.assertEqual(self.upload("a.png", self.picture(), mode="ai").get_json()["text"], LONG_TEXT)

    def test_blocked_ai_without_fallback_shows_reason(self):
        self.register()
        self.key.return_value = "kunci"
        with mock.patch.object(web, "groq_completion", side_effect=RuntimeError("Akses Groq ditolak.")), mock.patch.object(web, "local_ocr_text", side_effect=OSError("x")):
            response = self.upload("a.png", self.picture(), mode="ai")
        self.assertEqual((response.status_code, response.get_json()["error"]), (503, "Akses Groq ditolak."))

    def test_photo_needs_consent_before_leaving_server(self):
        self.register()
        self.key.return_value = "kunci"
        with mock.patch.object(web, "groq_completion") as groq:
            response = self.upload("a.png", self.picture())
        self.assertEqual(response.status_code, 428)
        self.assertTrue(response.get_json()["needs_consent"])
        groq.assert_not_called()

    def test_photo_is_read_with_consent(self):
        self.register()
        self.key.return_value = "kunci"
        with mock.patch.object(web, "groq_completion", return_value="<think>x</think>" + LONG_TEXT) as groq:
            response = self.upload("a.png", self.picture(), mode="ai")
        self.assertEqual(response.get_json()["text"], LONG_TEXT)
        content = groq.call_args[0][1]
        self.assertTrue(content[1]["image_url"]["url"].startswith("data:image/jpeg;base64,"))

    def test_scanned_pdf_is_rendered_and_read(self):
        self.register()
        self.key.return_value = "kunci"
        raw = self.blank_pdf()
        self.assertEqual(self.upload("scan.pdf", raw).status_code, 428)
        with mock.patch.object(web, "groq_completion", return_value=LONG_TEXT):
            response = self.upload("scan.pdf", raw, mode="ai")
        self.assertEqual(response.get_json()["text"], LONG_TEXT)

    def test_broken_image_is_rejected(self):
        self.register()
        self.key.return_value = "kunci"
        self.assertEqual(self.upload("a.jpg", b"bukan gambar", mode="ai").status_code, 400)

    def test_unknown_format_is_rejected(self):
        self.register()
        self.assertEqual(self.upload("a.exe", b"xx").status_code, 415)


class EmailVerificationTests(Base):
    def setUp(self):
        super().setUp()
        env = mock.patch.dict(os.environ, {"BREVO_API_KEY": "k", "EMAIL_FROM": "dari@test.test", "PUBLIC_URL": "https://contoh.test"})
        env.start()
        self.addCleanup(env.stop)
        self.sent = []
        outer = self

        class Reply:
            status = 201

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

        def fake_urlopen(req, timeout=None):
            outer.assertEqual(req.full_url, "https://api.brevo.com/v3/smtp/email")
            outer.sent.append(json.loads(req.data.decode()))
            return Reply()
        web.urllib.request.urlopen.side_effect = fake_urlopen

    def signup(self, email=None):
        return self.post("/api/register", {"email": email or self.email, "password": "password-uji-1"})

    def link_path(self):
        return self.sent[-1]["textContent"].split("https://contoh.test")[1]

    def test_login_blocked_until_confirmed(self):
        data = self.signup().get_json()
        self.assertTrue(data["verify_required"])
        self.assertEqual(self.client.get("/api/whatsapp/status").status_code, 401)
        self.assertEqual(self.post("/api/login", {"email": self.email, "password": "password-uji-1"}).status_code, 403)
        response = self.client.get(self.link_path())
        self.assertEqual(response.headers["Location"], "/?verified=1")
        self.assertEqual(self.post("/api/login", {"email": self.email, "password": "password-uji-1"}).status_code, 200)

    def test_link_is_single_use(self):
        self.signup()
        path = self.link_path()
        self.client.get(path)
        self.assertEqual(self.client.get(path).headers["Location"], "/?verified=0")

    def test_recovery_cannot_skip_confirmation(self):
        code = self.signup().get_json()["recovery_code"]
        response = self.post("/api/recover", {"email": self.email, "code": code, "new_password": "password-baru-1"})
        self.assertEqual(response.status_code, 403)

    def test_owner_email_gets_role_only_after_confirmation(self):
        email = web.OWNER_EMAIL
        self.signup(email)
        web.init_db()
        role = lambda: web.connect_db().execute("SELECT role FROM users WHERE email=?", (email,)).fetchone()["role"]
        self.assertEqual(role(), "user")
        self.client.get(self.link_path())
        self.assertEqual(role(), "owner")

    def test_resend_reveals_nothing_about_accounts(self):
        self.assertEqual(self.post("/api/verify/resend", {"email": "tidakada@test.test"}).status_code, 200)
        self.assertEqual(self.sent, [])


class WhatsAppTests(Base):
    def setUp(self):
        super().setUp()
        env = mock.patch.dict(os.environ, WA_ENV)
        env.start()
        self.addCleanup(env.stop)
        reply = mock.patch.object(web, "whatsapp_reply")
        self.reply = reply.start()
        self.addCleanup(reply.stop)
        self.phone = "6281%07d" % Base.counter

    def hook(self, messages, secret="rahasia"):
        raw = json.dumps({"entry": [{"changes": [{"value": {"messages": messages}}]}]}).encode()
        signature = "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
        return self.client.post("/webhook/whatsapp", data=raw, headers={"X-Hub-Signature-256": signature, "Content-Type": "application/json"})

    def text(self, body, message_id):
        return {"from": self.phone, "id": "%s-%s" % (self.phone, message_id), "type": "text", "text": {"body": body}}

    def link(self):
        self.register()
        data = self.post("/api/whatsapp/link", {"consent": True}).get_json()
        self.hook([self.text("HUBUNGKAN " + data["code"], "link")])
        return data

    def test_not_configured_has_no_qr(self):
        self.register()
        with mock.patch.dict(os.environ, {"WHATSAPP_TOKEN": ""}):
            self.assertFalse(self.client.get("/api/whatsapp/status").get_json()["configured"])
            self.assertEqual(self.post("/api/whatsapp/link", {"consent": True}).status_code, 503)

    def test_webhook_verification(self):
        ok = self.client.get("/webhook/whatsapp?hub.mode=subscribe&hub.verify_token=cocok&hub.challenge=42")
        self.assertEqual((ok.status_code, ok.get_data(as_text=True)), (200, "42"))
        self.assertEqual(self.client.get("/webhook/whatsapp?hub.mode=subscribe&hub.verify_token=salah&hub.challenge=42").status_code, 403)

    def test_bad_signature_is_rejected(self):
        self.assertEqual(self.hook([self.text("halo", "x")], secret="palsu").status_code, 403)
        self.reply.assert_not_called()

    def test_link_needs_consent(self):
        self.register()
        self.assertEqual(self.post("/api/whatsapp/link", {}).status_code, 400)

    def test_qr_points_to_real_chat_link(self):
        self.register()
        data = self.post("/api/whatsapp/link", {"consent": True}).get_json()
        self.assertEqual(data["url"], "https://wa.me/62811000?text=HUBUNGKAN%20" + data["code"])
        self.assertTrue(data["qr"].startswith("data:image/svg+xml"))

    def test_qr_flow_links_number(self):
        self.link()
        status = self.client.get("/api/whatsapp/status").get_json()
        self.assertTrue(status["linked"])
        self.assertNotIn(self.phone, status["phone"])
        self.assertIn("terhubung", self.reply.call_args[0][1])

    def test_code_works_once(self):
        data = self.link()
        self.reply.reset_mock()
        self.phone = "62899%06d" % Base.counter
        self.hook([self.text("HUBUNGKAN " + data["code"], "again")])
        self.assertIn("tidak berlaku", self.reply.call_args[0][1])

    def test_duplicate_delivery_processed_once(self):
        self.link()
        self.reply.reset_mock()
        message = self.text("halo", "dup")
        self.hook([message])
        self.hook([message])
        self.assertEqual(self.reply.call_count, 1)

    def test_unlinked_number_gets_instructions(self):
        self.hook([self.text("halo", "asing")])
        self.assertIn("belum terhubung", self.reply.call_args[0][1])

    def test_document_saved_for_linked_user_and_question_answered(self):
        self.link()
        self.key.return_value = "kunci"
        with mock.patch.object(web, "whatsapp_download", return_value=LONG_TEXT.encode()), mock.patch.object(web, "groq_completion", return_value="Ringkasan singkat."):
            self.hook([{"from": self.phone, "id": self.phone + "-doc", "type": "document",
                        "document": {"id": "m1", "filename": "sewa.txt", "mime_type": "text/plain"}}])
        workspace = self.client.get("/api/workspace").get_json()
        self.assertEqual([d["name"] for d in workspace["documents"]], ["sewa.txt"])
        self.assertIn("Ringkasan singkat.", self.reply.call_args[0][1])
        answer = json.dumps({"answer": "Dendanya 2% per hari.", "quote": "Denda keterlambatan 2%"})
        with mock.patch.object(web, "groq_completion", return_value=answer):
            self.hook([self.text("Berapa dendanya?", "q")])
        self.assertIn("2% per hari", self.reply.call_args[0][1])

    def test_media_token_only_sent_to_meta_hosts(self):
        with mock.patch.object(web, "whatsapp_api", return_value={"url": "https://penyerang.example/x", "file_size": 5}):
            with self.assertRaises(web.ExtractError):
                web.whatsapp_download("m1")


if __name__ == "__main__":
    unittest.main()
