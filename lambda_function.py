import json
import os
import traceback
import uuid
import boto3
import logging
import base64
import jwt
import io
from typing import Dict, Any, Optional, Tuple
import multipart as python_multipart

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def parse_form(
    headers: Dict[str, Any], body: io.BytesIO, boundary: str
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    fields, files = {}, {}

    def on_field(field: Any) -> None:
        key = field.field_name.decode()
        value = field.value.decode()
        fields[key] = value

    def on_file(file: Any) -> None:
        key = file.field_name.decode()
        files[key] = file

    content_type = headers.get("Content-Type", headers.get("content-type"))
    if not content_type or boundary is None:
        raise ValueError("Your header misses Content-Type or boundary parameter")

    content_type_parts = content_type.split(";")
    new_headers = {
        "Content-Type": f"{content_type_parts[0].strip()};boundary={boundary}"
    }

    python_multipart.parse_form(
        headers=new_headers, input_stream=body, on_field=on_field, on_file=on_file
    )
    return fields, files


def decode_token(id_token: str) -> Dict[str, Any]:
    try:
        token = jwt.decode(id_token, options={"verify_signature": False})
    except jwt.DecodeError as e:
        raise ValueError(f"Invalid token: {str(e)}")
    return token


def verify_admin_group(token: Dict[str, Any]) -> None:
    if "Admin" not in token.get("cognito:groups", []):
        raise ValueError("You are not a member of the Admin group")


def upload_to_s3(
    s3_client: Any, bucket_name: str, file_name: str, file_content: bytes
) -> None:
    s3_client.put_object(
        Bucket=bucket_name,
        Key=file_name,
        Body=file_content,
        ContentType="image/png",
    )


def store_hotel_record(table: Any, hotel: Dict[str, Any]) -> None:
    """
    Store a hotel record in a DynamoDB table.

    Parameters:

    table (Any):
    The DynamoDB table to store the record in.

    hotel (Dict[str, Any]): The hotel record to store.
    """
    table.put_item(Item=hotel)


def error_response(
    status_code: int, error_message: str, headers: Dict[str, Any]
) -> Dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": headers,
        "body": json.dumps({"Error": error_message}),
    }


def extract_boundary(headers: Dict[str, Any]) -> Optional[str]:
    content_type = headers.get("Content-Type", headers.get("content-type", None))
    if not content_type or "boundary=" not in content_type:
        return None

    boundary = content_type.split("boundary=")[1].split(";")[0].strip()
    result: str = (
        boundary.strip('"')
        if boundary.startswith('"') and boundary.endswith('"')
        else boundary
    )
    return result


def publish_to_sns(hotel: Dict[str, Any]) -> None:
    sns_topic_arn = os.getenv("hotelCreationTopicArn")
    if sns_topic_arn is None:
        raise ValueError("Missing SNS topic ARN")

    sns_client = boto3.client("sns")
    try:
        sns_client.publish(TopicArn=sns_topic_arn, Message=json.dumps(hotel))
    except Exception as e:
        logger.error(f"Failed to publish to SNS: {str(e)}")
        raise e


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    response_headers = {
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "*",
    }

    request_headers = event["headers"]
    body = event.get("body")
    if body is None:
        return error_response(400, "Missing body in the request", response_headers)

    body = (
        base64.b64decode(body) if event.get("isBase64Encoded") else body.encode("utf-8")
    )
    boundary = extract_boundary(request_headers)
    if boundary is None:
        return error_response(400, "Unable to extract boundary", response_headers)

    try:
        fields, files = parse_form(request_headers, io.BytesIO(body), boundary)
    except ValueError as e:
        return error_response(400, str(e), response_headers)

    try:
        id_token = fields.get("idToken")
        if id_token is None:
            return error_response(401, "Missing id token", response_headers)
        token = decode_token(id_token)
        verify_admin_group(token)
    except ValueError as e:
        return error_response(401, str(e), response_headers)

    logger.info("Token verified, reading rest of the data and preparing upload")
    hotel_name = fields.get("hotelName")
    hotel_rating = fields.get("hotelRating")
    hotel_city = fields.get("hotelCity")
    hotel_price = fields.get("hotelPrice")

    if (
        hotel_price is None
        or hotel_rating is None
        or hotel_name is None
        or hotel_city is None
    ):
        return error_response(
            400,
            "Missing hotel price or rating or name or city in the request",
            response_headers,
        )
    user_id = fields.get("userId")
    file = files.get("photo")
    if file is None:
        return error_response(400, "Missing photo in the request", response_headers)
    file_name = file.file_name.decode()
    file.file_object.seek(0)

    file_content = file.file_object.read()
    bucket_name = os.getenv("BUCKET_NAME")
    if bucket_name is None:
        return error_response(500, "Missing bucket name", response_headers)

    s3_client = boto3.client("s3", region_name=os.getenv("AWS_REGION"))
    table = boto3.resource("dynamodb", region_name=os.getenv("AWS_REGION")).Table(
        os.getenv("TABLE_NAME")
    )

    try:
        # Upload the image to S3
        upload_to_s3(s3_client, bucket_name, file_name, file_content)

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

        publish_to_sns(hotel)

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
