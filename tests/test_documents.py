import io

import boto3
import pytest
from moto import mock_aws

from app.documents import (
    MAX_UPLOAD_BYTES, list_s3_documents, make_object_key, upload_to_s3, validate_upload,
)

REGION = "ap-southeast-2"
BUCKET = "test-namawin-docs"
FAKE_KMS_KEY = "arn:aws:kms:ap-southeast-2:111122223333:key/00000000-0000-0000-0000-000000000000"


def test_validate_upload_sanitises_filename():
    assert validate_upload("../../etc/report.pdf", b"x") == ("etc_report.pdf", "pdf")


@pytest.mark.parametrize("name", ["evil.exe", "script.html", "noextension", ""])
def test_validate_upload_rejects_bad_types(name):
    with pytest.raises(ValueError):
        validate_upload(name, b"x")


def test_validate_upload_rejects_large_and_empty_files():
    with pytest.raises(ValueError):
        validate_upload("big.pdf", b"x" * (MAX_UPLOAD_BYTES + 1))
    with pytest.raises(ValueError):
        validate_upload("empty.txt", b"")


def test_object_key_format():
    key = make_object_key("user-123", "report.pdf")
    user_id, rest = key.split("/")
    assert user_id == "user-123"
    assert rest.endswith("-report.pdf") and len(rest) == 36 + 1 + len("report.pdf")


@mock_aws
def test_s3_upload_is_encrypted_with_kms():
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket=BUCKET, CreateBucketConfiguration={"LocationConstraint": REGION})

    key = make_object_key("user-123", "statement.txt")
    upload_to_s3(s3, BUCKET, key, b"hello", "text/plain", FAKE_KMS_KEY)
    upload_to_s3(s3, BUCKET, make_object_key("someone-else", "x.txt"), b"x", "text/plain", FAKE_KMS_KEY)

    docs = list_s3_documents(s3, BUCKET, "user-123/")
    assert len(docs) == 1  # only this user's prefix
    assert docs[0]["name"] == "statement.txt"
    assert docs[0]["encryption"] == "aws:kms"
    assert docs[0]["kms_key"] == FAKE_KMS_KEY


def test_local_upload_and_list(client):
    response = client.post(
        "/documents",
        data={"file": (io.BytesIO(b"hello"), "notes.txt")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 302
    page = client.get("/documents")
    assert b"notes.txt" in page.data


def test_local_upload_rejects_disallowed_type(client):
    client.post("/documents", data={"file": (io.BytesIO(b"MZ"), "evil.exe")},
                content_type="multipart/form-data")
    page = client.get("/documents")
    assert b"Only PDF, PNG, JPG and TXT" in page.data
    assert b"evil.exe" not in page.data.split(b"<h2>Your files</h2>")[1]
