
# Providers
provider "aws" {
  region = var.AWS_DEFAULT_REGION
}

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.53"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.35.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "2.16.1"
    }
  }
  backend "http" {
    # address        = "https://gitlab.com/api/v4/projects/${CI_PROJECT_ID}/terraform/state/default"
    # lock_address   = "https://gitlab.com/api/v4/projects/${CI_PROJECT_ID}/terraform/state/default/lock"
    # unlock_address = "https://gitlab.com/api/v4/projects/${CI_PROJECT_ID}/terraform/state/default/lock"
  }
}

provider "helm" {
  kubernetes {
    host                   = data.aws_eks_cluster.eks.endpoint
    cluster_ca_certificate = base64decode(data.aws_eks_cluster.eks.certificate_authority[0].data)
    token                  = data.aws_eks_cluster_auth.eks.token
  }
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.eks.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.eks.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.eks.token
}
