#
# Lambda Packaging
#
# Builds the Lambda zip artifact
resource "null_resource" "build_lambda" {
  # Trigger a rebuild on any variable change
  triggers = {
  }

  provisioner "local-exec" {
    command = local.build_lambda_command
  }
}

# Copies the artifact to the root directory
resource "null_resource" "copy_lambda_artifact" {
  depends_on = [null_resource.build_lambda]
  triggers = {
    vendor                  = var.auth_vendor
    cloudfront_distribution = var.cloudfront_distribution
    client_id               = var.client_id
    client_secret           = var.client_secret
    redirect_uri            = var.redirect_uri
    hd                      = var.hd
    session_duration        = var.session_duration
    authz                   = var.authz
    github_organization     = try(var.github_organization, "")
  }

  provisioner "local-exec" {
    command = <<EOT
    ${locals.build_lambda_command}
    cp ${path.module}/build/cloudfront-auth/distributions/${var.cloudfront_distribution}/${var.cloudfront_distribution}.zip ${local.lambda_filename}
    EOT
  }
}

# workarout to sync file creation
data "null_data_source" "lambda_artifact_sync" {
  inputs = {
    file    = local.lambda_filename
    trigger = null_resource.copy_lambda_artifact.id # this is for sync only
  }
}

data "local_file" "build-js" {
  filename = "${path.module}/build.js"
}

#
# S3
#
resource "aws_s3_bucket" "log_bucket" {
  bucket = "${var.bucket_name}-logging"
  acl    = "log-delivery-write"

  lifecycle_rule {
    id      = "log"
    prefix  = "log/"
    enabled = true

    tags = {
      rule      = "log"
      autoclean = true
    }

    expiration {
      days = 90
    }
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_s3_bucket" "default" {
  bucket = var.bucket_name
  acl    = "private"
  tags   = var.tags

  logging {
    target_bucket = aws_s3_bucket.log_bucket.id
    target_prefix = "log/static_site_s3/"
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

}

# Block direct public access
resource "aws_s3_bucket_public_access_block" "log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_public_access_block" "default" {
  bucket = aws_s3_bucket.default.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "s3_bucket_policy" {
  statement {
    actions = [
      "s3:GetObject",
    ]

    resources = [
      "${aws_s3_bucket.default.arn}/*",
    ]

    principals {
      type = "AWS"
      identifiers = [
        aws_cloudfront_origin_access_identity.default.iam_arn,
      ]
    }
  }

  statement {
    actions = [
      "s3:ListBucket",
    ]

    resources = [
      aws_s3_bucket.default.arn,
    ]

    principals {
      type = "AWS"
      identifiers = [
        aws_cloudfront_origin_access_identity.default.iam_arn,
      ]
    }
  }
}

resource "aws_s3_bucket_policy" "bucket_policy" {
  bucket = aws_s3_bucket.default.id
  policy = data.aws_iam_policy_document.s3_bucket_policy.json
}

#
# Cloudfront
#
resource "aws_cloudfront_origin_access_identity" "default" {
  comment = var.bucket_name
}

resource "aws_cloudfront_distribution" "default" {
  origin {
    domain_name = aws_s3_bucket.default.bucket_regional_domain_name
    origin_id   = local.s3_origin_id

    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.default.cloudfront_access_identity_path
    }
  }

  aliases = concat([var.cloudfront_distribution], [var.bucket_name], var.cloudfront_aliases)

  comment             = "Managed by Terraform"
  default_root_object = var.cloudfront_default_root_object
  enabled             = true
  http_version        = "http2"
  is_ipv6_enabled     = true
  price_class         = var.cloudfront_price_class
  tags                = var.tags

  logging_config {
    include_cookies = false
    bucket          = aws_s3_bucket.log_bucket.id
    prefix          = "logs/static_site_cf/"
  }

  default_cache_behavior {
    target_origin_id = local.s3_origin_id

    // Read only
    allowed_methods = [
      "GET",
      "HEAD",
    ]

    cached_methods = [
      "GET",
      "HEAD",
    ]

    forwarded_values {
      query_string = false
      headers = [
        "Access-Control-Request-Headers",
        "Access-Control-Request-Method",
        "Origin"
      ]

      cookies {
        forward = "none"
      }
    }

    lambda_function_association {
      event_type = "viewer-request"
      lambda_arn = aws_lambda_function.default.qualified_arn
    }

    viewer_protocol_policy = "redirect-to-https"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
      locations        = []
    }
  }

  # Handle the case where no certificate ARN provided
  dynamic "viewer_certificate" {
    for_each = (var.cloudfront_acm_certificate_arn == null ? { use_acm = false } : {})

    content {
      ssl_support_method             = "sni-only"
      cloudfront_default_certificate = true
      minimum_protocol_version       = "TLSv1.2_2021"
    }
  }

  # Handle the case where certificate ARN was provided
  dynamic "viewer_certificate" {
    for_each = (var.cloudfront_acm_certificate_arn != null ? { use_acm = true } : {}
    )
    content {
      ssl_support_method             = "sni-only"
      acm_certificate_arn            = var.cloudfront_acm_certificate_arn
      cloudfront_default_certificate = false
      minimum_protocol_version       = "TLSv1.2_2021"
    }
  }
}

#
# Lambda
#
data "aws_iam_policy_document" "lambda_log_access" {
  // Allow lambda access to logging
  statement {
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = [
      "arn:aws:logs:*:*:*",
    ]

    effect = "Allow"
  }
}

# This function is created in us-east-1 as required by CloudFront.
resource "aws_lambda_function" "default" {
  provider = aws.us-east-1

  description      = "Managed by Terraform"
  runtime          = "nodejs12.x"
  role             = aws_iam_role.lambda_role.arn
  filename         = local.lambda_filename
  function_name    = "cloudfront_auth"
  handler          = "index.handler"
  publish          = true
  timeout          = 5
  source_code_hash = filebase64sha256(data.null_data_source.lambda_artifact_sync.outputs["file"])
  tags             = var.tags

  depends_on = [null_resource.copy_lambda_artifact]
}

data "aws_iam_policy_document" "lambda_assume_role" {
  // Trust relationships taken from blueprint
  // Allow lambda to assume this role.
  statement {
    actions = [
      "sts:AssumeRole",
    ]

    principals {
      type = "Service"
      identifiers = [
        "edgelambda.amazonaws.com",
        "lambda.amazonaws.com",
      ]
    }

    effect = "Allow"
  }
}

resource "aws_iam_role" "lambda_role" {
  name               = "lambda_role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

# Attach the logging access document to the above role.
resource "aws_iam_role_policy_attachment" "lambda_log_access" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_log_access.arn
}

# Create an IAM policy that will be attached to the role
resource "aws_iam_policy" "lambda_log_access" {
  name   = "cloudfront_auth_lambda_log_access"
  policy = data.aws_iam_policy_document.lambda_log_access.json
}
