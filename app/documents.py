# OWNER: Ashwin (data and application security)
"""Document upload to S3, encrypted with a customer-managed KMS key (SSE-KMS).

Local mode saves files under ./local_uploads/ instead, so no AWS is needed.
Object keys look like:  <user_id>/<uuid>-<sanitised filename>
so each user's files sit under their own prefix and names never collide.
"""
import logging
import uuid
from pathlib import Path

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from flask import Blueprint, current_app, flash, g, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

from .auth import require_auth
from .logging_setup import log_security_event

bp = Blueprint("documents", __name__)
log = logging.getLogger(__name__)

MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MB
# Allowed extensions and the Content-Type we store (we never trust the browser's type).
ALLOWED_TYPES = {
    "pdf": "application/pdf",
    "png": "image/png",
    "jpg": "image/jpeg",
    "txt": "text/plain",
}
MAX_FILENAME_LENGTH = 100


def validate_upload(filename, data):
    """Return (safe_filename, extension) or raise ValueError with a friendly message."""
    # secure_filename strips paths and odd characters: "../../etc/passwd" -> "etc_passwd"
    safe_name = secure_filename(filename or "")
    if not safe_name or "." not in safe_name:
        raise ValueError("Please choose a file with an extension.")
    extension = safe_name.rsplit(".", 1)[1].lower()
    if extension not in ALLOWED_TYPES:
        raise ValueError("Only PDF, PNG, JPG and TXT files are allowed.")
    if len(data) == 0:
        raise ValueError("The file is empty.")
    if len(data) > MAX_UPLOAD_BYTES:
        raise ValueError("That file is too large. The limit is 5 MB.")
    # EXTENSION POINT: check the file's magic bytes match its extension, or
    # send it to a malware scanner before accepting it.
    return safe_name[-MAX_FILENAME_LENGTH:], extension


def make_object_key(user_id, safe_name):
    return f"{user_id}/{uuid.uuid4()}-{safe_name}"


def display_name(key):
    """'<user_id>/<36-char uuid>-report.pdf' -> 'report.pdf'"""
    return key.split("/", 1)[1][37:]


# ---------------------------------------------------------------------------
# S3 (AWS mode). These take the client as a parameter so tests can use moto.
# ---------------------------------------------------------------------------

def _s3_client():
    return boto3.client("s3", region_name=current_app.config["AWS_REGION"])


def upload_to_s3(s3, bucket, key, data, content_type, kms_key_id):
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=data,
        ContentType=content_type,
        ServerSideEncryption="aws:kms",  # encrypt at rest with KMS ...
        SSEKMSKeyId=kms_key_id,  # ... using OUR customer-managed key
    )


def list_s3_documents(s3, bucket, prefix):
    """List the user's objects and read each one's encryption status with head_object."""
    response = s3.list_objects_v2(Bucket=bucket, Prefix=prefix, MaxKeys=50)
    documents = []
    for obj in response.get("Contents", []):
        head = s3.head_object(Bucket=bucket, Key=obj["Key"])
        documents.append({
            "name": display_name(obj["Key"]),
            "key": obj["Key"],
            "size": obj["Size"],
            "uploaded": obj["LastModified"],
            "encryption": head.get("ServerSideEncryption", "none"),
            "kms_key": head.get("SSEKMSKeyId", ""),
        })
        # EXTENSION POINT: also show head.get("VersionId") to prove bucket
        # versioning is on, and warn if encryption is not "aws:kms".
    return documents


# ---------------------------------------------------------------------------
# Local disk (local mode)
# ---------------------------------------------------------------------------

def _local_path(upload_dir, key):
    base = Path(upload_dir).resolve()
    path = (base / key).resolve()
    if base not in path.parents:  # defence in depth against path traversal
        raise ValueError("Invalid file path.")
    return path


def save_locally(upload_dir, key, data):
    path = _local_path(upload_dir, key)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def list_local_documents(upload_dir, user_id):
    user_dir = _local_path(upload_dir, f"{user_id}/x").parent
    if not user_dir.is_dir():
        return []
    return [
        {
            "name": display_name(f"{user_id}/{path.name}"),
            "key": f"{user_id}/{path.name}",
            "size": path.stat().st_size,
            "uploaded": None,
            "encryption": "none (local mode)",
            "kms_key": "",
        }
        for path in sorted(user_dir.iterdir())
    ]


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------

@bp.route("/documents", methods=["GET", "POST"])
@require_auth
def index():
    cfg = current_app.config
    use_s3 = cfg["APP_ENV"] == "aws"

    if use_s3 and not (cfg["S3_BUCKET"] and cfg["KMS_KEY_ID"]):
        flash("Document storage is not configured (S3_BUCKET and KMS_KEY_ID).", "error")
        return render_template("documents.html", documents=[]), 503

    if request.method == "POST":
        upload = request.files.get("file")
        if upload is None:
            flash("Please choose a file.", "error")
            return redirect(url_for("documents.index"))

        data = upload.read(MAX_UPLOAD_BYTES + 1)  # read one extra byte to detect "too big"
        try:
            safe_name, extension = validate_upload(upload.filename, data)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("documents.index"))

        key = make_object_key(g.user_id, safe_name)
        try:
            if use_s3:
                upload_to_s3(_s3_client(), cfg["S3_BUCKET"], key, data,
                             ALLOWED_TYPES[extension], cfg["KMS_KEY_ID"])
            else:
                save_locally(cfg["LOCAL_UPLOAD_DIR"], key, data)
        except (ClientError, BotoCoreError):
            log.exception("Upload failed")
            flash("Upload failed. Please try again later.", "error")
            return redirect(url_for("documents.index"))

        log_security_event("document_uploaded", user_id=g.user_id, key=key,
                           size=len(data), storage="s3" if use_s3 else "local")
        flash(f"Uploaded {safe_name}.", "success")
        return redirect(url_for("documents.index"))

    try:
        if use_s3:
            documents = list_s3_documents(_s3_client(), cfg["S3_BUCKET"], f"{g.user_id}/")
        else:
            documents = list_local_documents(cfg["LOCAL_UPLOAD_DIR"], g.user_id)
    except (ClientError, BotoCoreError):
        log.exception("Listing documents failed")
        flash("Could not load your documents.", "error")
        documents = []

    return render_template("documents.html", documents=documents)
