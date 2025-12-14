# EC2 Instance Configuration

# Security Group for the application
resource "aws_security_group" "app_sg" {
  name        = "cra-scam-detection-sg"
  description = "Security group for CRA Scam Detection app"

  # SSH access
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  # API port
  ingress {
    description = "API"
    from_port   = var.app_port
    to_port     = var.app_port
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Frontend port (if running dev server)
  ingress {
    description = "Frontend"
    from_port   = var.frontend_port
    to_port     = var.frontend_port
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # HTTP (for future nginx/reverse proxy)
  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # HTTPS (for future SSL)
  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "cra-scam-detection-sg"
  }
}

# EC2 Instance
resource "aws_instance" "app_server" {
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = var.instance_type
  key_name               = var.key_pair_name
  vpc_security_group_ids = [aws_security_group.app_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile.name

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = <<-EOF
              #!/bin/bash
              # Update system
              dnf update -y

              # Install Node.js 20
              dnf install -y nodejs npm git

              # Install PM2 globally
              npm install -g pm2

              # Create app directory
              mkdir -p /home/ec2-user/cra-aws-scams
              chown ec2-user:ec2-user /home/ec2-user/cra-aws-scams

              # Set environment variables
              echo "export AWS_REGION=${var.aws_region}" >> /home/ec2-user/.bashrc
              echo "export NODE_ENV=production" >> /home/ec2-user/.bashrc
              EOF

  tags = {
    Name = "cra-scam-detection-${var.environment}"
  }
}

# Elastic IP (optional - uncomment if you want a static IP)
# resource "aws_eip" "app_eip" {
#   instance = aws_instance.app_server.id
#   domain   = "vpc"
#
#   tags = {
#     Name = "cra-scam-detection-eip"
#   }
# }
