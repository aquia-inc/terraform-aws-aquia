resource "aws_instance" "example" {
  ami           = "ami-12345678"
  instance_type = "t2.nanoo" # <-- typo: "nanoo" is invalid
}
