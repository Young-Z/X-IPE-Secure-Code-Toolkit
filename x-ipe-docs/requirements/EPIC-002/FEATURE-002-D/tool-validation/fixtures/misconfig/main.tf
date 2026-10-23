# Self-authored misconfiguration fixture
resource "aws_s3_bucket" "demo" {
  bucket = "demo-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "demo" {
  name = "demo"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
