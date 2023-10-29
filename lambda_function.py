import json
import os
import traceback
import uuid
import boto3
import logging
import base64
import jwt
import io
from typing import Dict, Any
import multipart as python_multipart

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def parse_form(headers, body, boundary):
    fields, files = {}, {}

    def on_field(field):
        key = field.field_name.decode()
        value = field.value.decode()
        fields[key] = value

    def on_file(file):
        key = file.field_name.decode()
        files[key] = file

    logger.info("parse headers: %s", headers)
    content_type = headers.get("Content-Type")
    if not content_type:
        content_type = headers.get("content-type")
    if not content_type:
        logger.warning("Your header misses Content-Type")
        raise ValueError("Your header misses Content-Type")
    if boundary is None:
        logger.warning("Your header misses boundary parameter")
        raise ValueError("Your header misses boundary parameter")

    # Extract the multipart/form-data part and remove whitespace
    content_type_parts = content_type.split(";")
    content_type_part = content_type_parts[0].strip()
    boundary_part = f"boundary={boundary}"

    # Update the headers with the modified Content-Type value
    new_headers: Dict[str, Any] = {}
    new_headers["Content-Type"] = f"{content_type_part};{boundary_part}"

    python_multipart.parse_form(
        headers=new_headers, input_stream=body, on_field=on_field, on_file=on_file
    )
    return fields, files


def decode_token(id_token):
    try:
        token = jwt.decode(id_token, options={"verify_signature": False})
    except jwt.exceptions.DecodeError:
        raise ValueError("Invalid token")
    return token


def verify_admin_group(token):
    group = token.get("cognito:groups")
    if group is None or "Admin" not in group:
        raise ValueError("You are not a member of the Admin group")


def upload_to_s3(bucket_name, file_name, file_object):
    s3_client = boto3.client("s3", region_name=os.getenv("AWS_REGION"))
    s3_client.put_object(Bucket=bucket_name, Key=file_name, Body=file_object.read())


def store_hotel_record(table, hotel):
    table.put_item(Item=hotel)


def handler(event, context):
    response_headers = {
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "*",
    }

    request_headers = event["headers"]
    logger.info(f"request_headers: {request_headers}")
    body = event["body"]
    if bool(event.get("isBase64Encoded")):
        body = base64.b64decode(body)
    else:
        body = body.encode("utf-8")

    boundary = extract_boundary(request_headers)
    logger.info(f"boundary: {boundary}")
    if boundary is None:
        raise ValueError("Unable to extract boundary")
    try:
        fields, files = parse_form(request_headers, io.BytesIO(body), boundary)
    except ValueError as e:
        return {
            "statusCode": 400,
            "headers": response_headers,
            "body": json.dumps({"Error": str(e)}),
        }

    id_token = fields.get("idToken")
    logger.info(f"attempting to decode token {id_token}")
    try:
        token = decode_token(id_token)
        verify_admin_group(token)
    except ValueError as e:
        return {
            "statusCode": 401,
            "headers": response_headers,
            "body": json.dumps({"Error": str(e)}),
        }

    logger.info("Token verified, reading rest of the data and preparing upload")
    hotel_name = fields.get("hotelName")
    hotel_rating = fields.get("hotelRating")
    hotel_city = fields.get("hotelCity")
    hotel_price = fields.get("hotelPrice")
    user_id = fields.get("userId")
    file = files.get("photo")
    file_name = file.file_name.decode()
    file.file_object.seek(0)

    bucket_name = os.getenv("BUCKET_NAME")
    table = boto3.resource("dynamodb", region_name=os.getenv("AWS_REGION")).Table(
        os.getenv("TABLE_NAME")
    )

    logger.info(bucket_name)
    try:
        # Upload the image to S3
        upload_to_s3(bucket_name, file_name, file.file_object)

        hotel = {
            "userId": user_id,
            "Id": str(uuid.uuid4()),
            "Name": hotel_name,
            "CityName": hotel_city,
            "Price": int(hotel_price),
            "Rating": int(hotel_rating),
            "FileName": file_name,
        }

        # Store the hotel record in DynamoDb
        store_hotel_record(table, hotel)

    except Exception as e:
        logger.error(traceback.format_exc())
        return {
            "statusCode": 500,
            "headers": response_headers,
            "body": json.dumps({"Error": str(e)}),
        }

    return {
        "statusCode": 200,
        "headers": response_headers,
        "body": json.dumps({"message": "OK"}),
    }


def extract_boundary(headers):
    logger.info(f"headers in extract_boundary: {headers}")
    content_type = headers.get("Content-Type")
    if not content_type:
        content_type = headers.get("content-type")
    boundary_start = content_type.find("boundary=")
    if boundary_start != -1:
        boundary_end = content_type.find(";", boundary_start)
        if boundary_end == -1:
            boundary_end = len(content_type)
        boundary = content_type[boundary_start + len("boundary=") : boundary_end].strip()

        # Check if the boundary is enclosed in quotes and remove them if present
        if boundary.startswith('"') and boundary.endswith('"'):
            boundary = boundary[1:-1]

        return boundary

    return None
