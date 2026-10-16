import json

import boto3
import pytest
from moto import mock_aws

from app.secrets import load_app_secret_key, load_db_credentials

REGION = "ap-southeast-2"


@mock_aws
def test_load_db_credentials_from_standard_rds_secret():
    client = boto3.client("secretsmanager", region_name=REGION)
    client.create_secret(Name="test/db", SecretString=json.dumps({
        "engine": "mysql", "username": "app", "password": "s3cret",
        "host": "db.example.internal", "port": 3306, "dbname": "namawin",
    }))
    creds = load_db_credentials("test/db", REGION)
    assert creds == {"username": "app", "password": "s3cret", "host": "db.example.internal",
                     "port": 3306, "dbname": "namawin"}


@mock_aws
def test_missing_keys_error_does_not_leak_values():
    client = boto3.client("secretsmanager", region_name=REGION)
    client.create_secret(Name="test/db", SecretString=json.dumps({"password": "s3cret"}))
    with pytest.raises(RuntimeError) as excinfo:
        load_db_credentials("test/db", REGION)
    assert "username" in str(excinfo.value)
    assert "s3cret" not in str(excinfo.value)


@mock_aws
def test_app_secret_key_json_and_plain_text():
    client = boto3.client("secretsmanager", region_name=REGION)
    client.create_secret(Name="test/app-json", SecretString=json.dumps({"SECRET_KEY": "abc"}))
    client.create_secret(Name="test/app-plain", SecretString="plain-key")
    assert load_app_secret_key("test/app-json", REGION) == "abc"
    assert load_app_secret_key("test/app-plain", REGION) == "plain-key"
