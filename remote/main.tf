# Local variables
locals {
  zoneA = "${var.AWS_DEFAULT_REGION}a"
  zoneB = "${var.AWS_DEFAULT_REGION}b"
  zoneC = "${var.AWS_DEFAULT_REGION}c"
}

# Variables
variable "deploy_metrics_server" {
  description = "Flag to control metrics server deployment"
  type        = bool
  default     = false
}

variable "create_repo_1_connection_key_secret" {
  description = "Flag to create a connection secret for repository #1"
  type        = bool
  default     = false
}

variable "create_repo_2_connection_key_secret" {
  description = "Flag to create a connection secret for repository #2"
  type        = bool
  default     = false
}

variable "aws_eks_cluster_version" {
  description = "EKS cluster version"
  type        = string
}

variable "aws_eks_cluster_name" {
  description = "EKS cluster name"
  type        = string
}

variable "create_developer_user" {
  description = "Flag to control developer user creation"
  type        = bool
  default     = true
}

variable "create_manager_user" {
  description = "Flag to control manager user creation"
  type        = bool
  default     = true
}

variable "create_lbc" {
  description = "Flag to load balancer controller deployment"
  type        = bool
  default     = true
}

variable "create_argocd" {
  description = "Flag to ArgoCD deployment"
  type        = bool
  default     = true
}

variable "env" {
  description = "Environment"
  type        = string
}

variable "aws_lbc_sa" {
  description = "Flag to load balancer controller deployment"
  type        = string
  default     = "aws-load-balancer-controller"
}

variable "hosted_zone_id" {
  description = "Hosted zone ID"
  type        = string
}

variable "argocd_certificate" {
  description = "ArgoCD certificate"
  type        = string
}

variable "deploy_argocd_route53_record" {
  description = "Flag to control ArgoCD Route53 record"
  type        = bool
  default     = true
}

variable "deploy_local_file_elb_hosted_zone_id" {
  description = "Flag to 'deploy data.local_file' 'elb_hosted_zone_id'"
  type        = bool
  default     = true
}

variable "deploy_terraform_data_elb_hosted_zone_id" {
  description = "Flag to 'deploy 'resource.terraform_data' 'extract_elb_hosted_zone_id'"
  type        = bool
  default     = true
}

variable "deploy_data_kubernetes_ingress_v1_argocd_ingress" {
  description = "Flag to 'deploy 'data.kubernetes_ingress_v1' 'argocd_ingress'"
  type        = bool
  default     = true
}

variable "manager_user" {
  description = "User with manager privileges"
  type        = string
}

variable "developer_user" {
  description = "User with developer privileges"
  type        = string
}

variable "argocd_helm_chart_version" {
  description = "ArgoCD Helm chart version"
  type        = string
}

variable "argocd_hostname" {
  description = "ArgoCD hostname"
  type        = string
}

variable "repo_1_ssh_key" {
  description = "Repository #1 SSH key"
  type        = string
}

variable "repo_2_ssh_key" {
  description = "Repository #2 SSH key"
  type        = string
}

variable "repo_1_name" {
  description = "Repository #1 name"
  type        = string
}

variable "repo_2_name" {
  description = "Repository #2 name"
  type        = string
}

variable "repo_1_url" {
  description = "Repository #1 URL"
  type        = string
}

variable "repo_2_url" {
  description = "Repository #2 URL"
  type        = string
}

variable "AWS_DEFAULT_REGION" {
  description = "AWS region"
  type        = string
}

variable "aws_lbc_helm_chart_version" {
  description = "AWS LBC Helm chart version"
  type        = string
}

variable "CI_PROJECT_ID" {
  description = "Project ID"
  type        = string
}

variable "script_elb_hosted_zone_id" {
  description = "Name of the script to extract a Hosted Zone ID of ArgoCD Load Balancer"
  type        = string
}

variable "argocd_lb_name" {
  description = "ArgoCD LoadBalancer name"
  type        = string
}

variable "deploy_local_file_elb_hosted_zone_id" {
  description = "Flag to 'deploy data.local_file' 'elb_hosted_zone_id'"
  type        = bool
  default     = true
}

variable "local_file_elb_hosted_zone_id" {
  description = "Name of the local file to save a Hosted Zone ID of ArgoCD Load Balancer"
  type        = string
}

# Data
data "aws_eks_cluster" "eks" {
  name = aws_eks_cluster.eks.name
}

data "aws_eks_cluster_auth" "eks" {
  name = aws_eks_cluster.eks.name
}

data "tls_certificate" "eks" {
  url = aws_eks_cluster.eks.identity[0].oidc[0].issuer
}

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

# Networking
resource "aws_vpc" "aws-vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "${var.env}-vpc"
  }
}

resource "aws_internet_gateway" "aws-igw" {
  vpc_id = aws_vpc.aws-vpc.id
  tags = {
    Name = "${var.env}-igw"
  }
}

resource "aws_subnet" "privateA" {
  vpc_id            = aws_vpc.aws-vpc.id
  cidr_block        = "10.0.0.0/19"
  availability_zone = local.zoneA
  tags = {
    Name                                                             = "${var.env}-private-${local.zoneA}"
    "kubernetes.io/role/internal-elb"                                = "1"
    "kubernetes.io/cluster/${var.env}-${var.aws_eks_cluster_name}" = "owned"
  }
}

resource "aws_subnet" "privateB" {
  vpc_id            = aws_vpc.aws-vpc.id
  cidr_block        = "10.0.32.0/19"
  availability_zone = local.zoneB
  tags = {
    Name                                                             = "${var.env}-private-${local.zoneB}"
    "kubernetes.io/role/internal-elb"                                = "1"
    "kubernetes.io/cluster/${var.env}-${var.aws_eks_cluster_name}" = "owned"
  }
}

resource "aws_subnet" "privateC" {
  vpc_id            = aws_vpc.aws-vpc.id
  cidr_block        = "10.0.64.0/19"
  availability_zone = local.zoneC
  tags = {
    Name                                                           = "${var.env}-private-${local.zoneC}"
    "kubernetes.io/role/internal-elb"                              = "1"
    "kubernetes.io/cluster/${var.env}-${var.aws_eks_cluster_name}" = "owned"
  }
}


resource "aws_subnet" "publicA" {
  vpc_id                  = aws_vpc.aws-vpc.id
  cidr_block              = "10.0.96.0/19"
  availability_zone       = local.zoneA
  map_public_ip_on_launch = true
  tags = {
    Name                                                           = "${var.env}-private-${local.zoneA}"
    "kubernetes.io/role/elb"                                       = "1"
    "kubernetes.io/cluster/${var.env}-${var.aws_eks_cluster_name}" = "owned"
  }
}

resource "aws_subnet" "publicB" {
  vpc_id                  = aws_vpc.aws-vpc.id
  cidr_block              = "10.0.128.0/19"
  availability_zone       = local.zoneB
  map_public_ip_on_launch = true
  tags = {
    Name                                                           = "${var.env}-private-${local.zoneB}"
    "kubernetes.io/role/elb"                                       = "1"
    "kubernetes.io/cluster/${var.env}-${var.aws_eks_cluster_name}" = "owned"
  }
}

resource "aws_subnet" "publicC" {
  vpc_id                  = aws_vpc.aws-vpc.id
  cidr_block              = "10.0.160.0/19"
  availability_zone       = local.zoneC
  map_public_ip_on_launch = true
  tags = {
    Name                                                             = "${var.env}-private-${local.zoneC}"
    "kubernetes.io/role/elb"                                         = "1"
    "kubernetes.io/cluster/${var.env}-${var.aws_eks_cluster_name}" = "owned"
  }
}

resource "aws_eip" "aws-eip" {
  domain = "vpc"
  tags = {
    Name = "${var.env}-nat"
  }
}

resource "aws_nat_gateway" "aws-nat-gw" {
  allocation_id = aws_eip.aws-eip.id
  subnet_id     = aws_subnet.publicA.id
  tags = {
    Name = "${var.env}-nat"
  }
  depends_on = [
    aws_internet_gateway.aws-igw
  ]
}

resource "aws_route_table" "aws-rt-private" {
  vpc_id = aws_vpc.aws-vpc.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.aws-nat-gw.id
  }
  tags = {
    Name = "${var.env}-private"
  }
}

resource "aws_route_table" "aws-rt-public" {
  vpc_id = aws_vpc.aws-vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.aws-igw.id
  }
  tags = {
    Name = "${var.env}-public"
  }
}

resource "aws_route_table_association" "privateA" {
  subnet_id      = aws_subnet.privateA.id
  route_table_id = aws_route_table.aws-rt-private.id
}

resource "aws_route_table_association" "privateB" {
  subnet_id      = aws_subnet.privateB.id
  route_table_id = aws_route_table.aws-rt-private.id
}

resource "aws_route_table_association" "privateC" {
  subnet_id      = aws_subnet.privateC.id
  route_table_id = aws_route_table.aws-rt-private.id
}

resource "aws_route_table_association" "publicA" {
  subnet_id      = aws_subnet.publicA.id
  route_table_id = aws_route_table.aws-rt-public.id
}

resource "aws_route_table_association" "publicB" {
  subnet_id      = aws_subnet.publicB.id
  route_table_id = aws_route_table.aws-rt-public.id
}

resource "aws_route_table_association" "publicC" {
  subnet_id      = aws_subnet.publicC.id
  route_table_id = aws_route_table.aws-rt-public.id
}

# EKS
resource "aws_iam_openid_connect_provider" "eks" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.eks.identity[0].oidc[0].issuer
  depends_on      = [aws_eks_cluster.eks]
}

resource "aws_iam_role" "eks" {
  name               = "${var.env}-${var.aws_eks_cluster_name}-eks-cluster"
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "eks.amazonaws.com"
      }
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "eks" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks.name
}

resource "aws_eks_cluster" "eks" {
  name     = "${var.env}-${var.aws_eks_cluster_name}"
  version  = var.aws_eks_cluster_version
  role_arn = aws_iam_role.eks.arn
  vpc_config {
    endpoint_private_access = false
    endpoint_public_access  = true

    subnet_ids = [
      aws_subnet.privateA.id,
      aws_subnet.privateB.id,
      aws_subnet.privateC.id
    ]
  }
  access_config {
    authentication_mode                         = "API"
    bootstrap_cluster_creator_admin_permissions = true
  }
  depends_on = [
    aws_iam_role_policy_attachment.eks
  ]
}

# Nodes
resource "aws_iam_role" "nodes" {
  name               = "${var.env}-${var.aws_eks_cluster_name}-eks-nodes"
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      }
    }
  ]
}
POLICY
}

# This policy now includes AssumeRoleForPodIdentity for the Pod Identity Agent
resource "aws_iam_role_policy_attachment" "amazon_eks_worker_node_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.nodes.name
}

resource "aws_iam_role_policy_attachment" "amazon_eks_cni_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.nodes.name
}

resource "aws_iam_role_policy_attachment" "amazon_ec2_container_registry_read_only" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.nodes.name
}

resource "aws_eks_node_group" "general" {
  cluster_name    = aws_eks_cluster.eks.name
  version         = var.aws_eks_cluster_version
  node_group_name = "general"
  node_role_arn   = aws_iam_role.nodes.arn
  subnet_ids = [
    aws_subnet.privateA.id,
    aws_subnet.privateB.id,
    aws_subnet.privateC.id
  ]
  capacity_type  = "SPOT"
  instance_types = ["t3.small"]
  scaling_config {
    desired_size = 2
    max_size     = 10
    min_size     = 1
  }
  update_config {
    max_unavailable = 1
  }
  labels = {
    role = "general"
  }
  depends_on = [
    aws_iam_role_policy_attachment.amazon_eks_worker_node_policy,
    aws_iam_role_policy_attachment.amazon_eks_cni_policy,
    aws_iam_role_policy_attachment.amazon_ec2_container_registry_read_only,
  ]
  # Allow external changes without Terraform plan difference
  lifecycle {
    ignore_changes = [scaling_config[0].desired_size]
  }
}

# K8S Roles & Role Bindings
## Developer
resource "kubernetes_cluster_role" "viewer" {
  metadata {
    name = "viewer"
  }
  rule {
    api_groups = ["*"]
    resources = [
      "namespaces",
      "pods",
      "configmaps",
      "secrets",
      "services"
    ]
    verbs = [
      "get",
      "list",
      "watch"
    ]
  }
}

resource "kubernetes_cluster_role_binding" "viewer-binding" {
  metadata {
    name = "viewer-binding"
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "cluster-admin"
  }
  subject {
    kind      = "Group"
    name      = "viewer-group"
    api_group = "rbac.authorization.k8s.io"
  }
}

## Manager
resource "kubernetes_cluster_role_binding" "admin-binding" {
  metadata {
    name = "admin-binding"
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "cluster-admin"
  }
  subject {
    kind      = "User"
    name      = "admin"
    api_group = "rbac.authorization.k8s.io"
  }
  subject {
    kind      = "ServiceAccount"
    name      = "default"
    namespace = "kube-system"
  }
  subject {
    kind      = "Group"
    name      = "manager-group"
    api_group = "rbac.authorization.k8s.io"
  }
}

# IAM
## Developer
resource "aws_iam_user" "developer" {
  count = var.create_developer_user ? 1 : 0
  name  = var.developer_user
}

resource "aws_iam_policy" "developer_eks" {
  count  = var.create_developer_user ? 1 : 0
  name   = "AmazonEKSDeveloperPolicy"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "eks:DescribeCluster",
        "eks:ListClusters"
      ],
      "Resource": "*"
    }
  ]
}
POLICY
}

resource "aws_iam_user_policy_attachment" "developer_eks" {
  count      = var.create_developer_user ? 1 : 0
  user       = aws_iam_user.developer[0].name
  policy_arn = aws_iam_policy.developer_eks[0].arn
}

resource "aws_eks_access_entry" "developer" {
  count             = var.create_developer_user ? 1 : 0
  cluster_name      = aws_eks_cluster.eks.name
  principal_arn     = aws_iam_user.developer[0].arn
  kubernetes_groups = ["viewer-group"]
}

## Manager
data "aws_caller_identity" "current" {}

resource "aws_iam_role" "eks_admin" {
  count              = var.create_manager_user ? 1 : 0
  name               = "${var.env}-${var.aws_eks_cluster_name}-eks-admin"
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Principal": {
        "AWS": "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      }
    }
  ]
}
POLICY
}

resource "aws_iam_policy" "eks_admin" {
  count  = var.create_manager_user ? 1 : 0
  name   = "AmazonEKSAdminPolicy"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "eks:*"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "iam:PassedToService": "eks.amazonaws.com"
        }
      }
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "eks_admin" {
  count      = var.create_manager_user ? 1 : 0
  role       = aws_iam_role.eks_admin[0].name
  policy_arn = aws_iam_policy.eks_admin[0].arn
}

resource "aws_iam_user" "manager" {
  count = var.create_manager_user ? 1 : 0
  name  = var.manager_user
}

resource "aws_iam_policy" "eks_assume_admin" {
  count  = var.create_manager_user ? 1 : 0
  name   = "AmazonEKSAssumeAdminPolicy"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
      {
          "Effect": "Allow",
          "Action": [
              "sts:AssumeRole"
          ],
          "Resource": "${aws_iam_role.eks_admin[0].arn}"
      }
  ]
}
POLICY
}

resource "aws_iam_user_policy_attachment" "manager" {
  count      = var.create_manager_user ? 1 : 0
  user       = aws_iam_user.manager[0].name
  policy_arn = aws_iam_policy.eks_assume_admin[0].arn
}

# Best practice: use IAM roles due to temporary credentials
resource "aws_eks_access_entry" "manager" {
  count             = var.create_manager_user ? 1 : 0
  cluster_name      = aws_eks_cluster.eks.name
  principal_arn     = aws_iam_role.eks_admin[0].arn
  kubernetes_groups = ["manager-group"]
}

# Metrics server
resource "helm_release" "metrics_server" {
  count            = var.deploy_metrics_server ? 1 : 0
  name             = "metrics-server"
  repository       = "https://charts.bitnami.com/bitnami"
  chart            = "metrics-server"
  namespace        = "metrics-server"
  version          = "7.2.16"
  create_namespace = true
  set {
    name  = "apiService.create"
    value = "true"
  }
  depends_on = [
    aws_eks_cluster.eks,
    aws_eks_node_group.general
  ]
}

# AWS LBC
data "aws_iam_policy_document" "aws_lbc" {
  count = var.create_lbc ? 1 : 0

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.eks.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub"

      values = [
        "system:serviceaccount:kube-system:${var.aws_lbc_sa}"
      ]
    }
    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud"

      values = [
        "sts.amazonaws.com"
      ]
    }
    effect = "Allow"
  }
}

resource "aws_iam_role" "aws_lbc" {
  count              = var.create_lbc ? 1 : 0
  name               = "${aws_eks_cluster.eks.name}-aws-lbc"
  assume_role_policy = data.aws_iam_policy_document.aws_lbc[0].json
}

resource "aws_iam_role_policy_attachment" "aws_lbc" {
  count      = var.create_lbc ? 1 : 0
  role       = aws_iam_role.aws_lbc[0].name
  policy_arn = aws_iam_policy.aws_lbc[0].arn
}

resource "aws_iam_policy" "aws_lbc" {
  count  = var.create_lbc ? 1 : 0
  name   = "AWSLoadBalancerController"
  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "iam:CreateServiceLinkedRole"
        ],
        "Resource": "*",
        "Condition": {
          "StringEquals": {
            "iam:AWSServiceName": "elasticloadbalancing.amazonaws.com"
          }
        }
      },
      {
        "Effect": "Allow",
        "Action": [
          "ec2:DescribeAccountAttributes",
          "ec2:DescribeAddresses",
          "ec2:DescribeAvailabilityZones",
          "ec2:DescribeInternetGateways",
          "ec2:DescribeVpcs",
          "ec2:DescribeVpcPeeringConnections",
          "ec2:DescribeSubnets",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeInstances",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeTags",
          "ec2:GetCoipPoolUsage",
          "ec2:DescribeCoipPools",
          "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:DescribeLoadBalancerAttributes",
          "elasticloadbalancing:DescribeListeners",
          "elasticloadbalancing:DescribeListenerCertificates",
          "elasticloadbalancing:DescribeSSLPolicies",
          "elasticloadbalancing:DescribeRules",
          "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:DescribeTargetGroupAttributes",
          "elasticloadbalancing:DescribeTargetHealth",
          "elasticloadbalancing:DescribeTags",
          "elasticloadbalancing:DescribeTrustStores",
          "elasticloadbalancing:DescribeListenerAttributes"
        ],
        "Resource": "*"
      },
      {
        "Effect": "Allow",
        "Action": [
          "cognito-idp:DescribeUserPoolClient",
          "acm:ListCertificates",
          "acm:DescribeCertificate",
          "iam:ListServerCertificates",
          "iam:GetServerCertificate",
          "waf-regional:GetWebACL",
          "waf-regional:GetWebACLForResource",
          "waf-regional:AssociateWebACL",
          "waf-regional:DisassociateWebACL",
          "wafv2:GetWebACL",
          "wafv2:GetWebACLForResource",
          "wafv2:AssociateWebACL",
          "wafv2:DisassociateWebACL",
          "shield:GetSubscriptionState",
          "shield:DescribeProtection",
          "shield:CreateProtection",
          "shield:DeleteProtection"
        ],
        "Resource": "*"
      },
      {
        "Effect": "Allow",
        "Action": [
          "ec2:GetSecurityGroupsForVpc",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupIngress"
        ],
        "Resource": "*"
      },
      {
        "Effect": "Allow",
        "Action": [
          "ec2:CreateSecurityGroup"
        ],
        "Resource": "*"
      },
      {
        "Effect": "Allow",
        "Action": [
          "ec2:CreateTags"
        ],
        "Resource": "arn:aws:ec2:*:*:security-group/*",
        "Condition": {
          "StringEquals": {
            "ec2:CreateAction": "CreateSecurityGroup"
          },
          "Null": {
            "aws:RequestTag/elbv2.k8s.aws/cluster": "false"
          }
        }
      },
      {
        "Effect": "Allow",
        "Action": [
          "ec2:CreateTags",
          "ec2:DeleteTags"
        ],
        "Resource": "arn:aws:ec2:*:*:security-group/*",
        "Condition": {
          "Null": {
            "aws:RequestTag/elbv2.k8s.aws/cluster": "true",
            "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
          }
        }
      },
      {
        "Effect": "Allow",
        "Action": [
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:DeleteSecurityGroup"
        ],
        "Resource": "*",
        "Condition": {
          "Null": {
            "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
          }
        }
      },
      {
        "Effect": "Allow",
        "Action": [
          "elasticloadbalancing:CreateLoadBalancer",
          "elasticloadbalancing:CreateTargetGroup"
        ],
        "Resource": "*",
        "Condition": {
          "Null": {
            "aws:RequestTag/elbv2.k8s.aws/cluster": "false"
          }
        }
      },
      {
        "Effect": "Allow",
        "Action": [
          "elasticloadbalancing:CreateListener",
          "elasticloadbalancing:DeleteListener",
          "elasticloadbalancing:CreateRule",
          "elasticloadbalancing:DeleteRule"
        ],
        "Resource": "*"
      },
      {
        "Effect": "Allow",
        "Action": [
          "elasticloadbalancing:AddTags",
          "elasticloadbalancing:RemoveTags"
        ],
        "Resource": [
          "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
          "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
          "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*"
        ],
        "Condition": {
          "Null": {
            "aws:RequestTag/elbv2.k8s.aws/cluster": "true",
            "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
          }
        }
      },
      {
        "Effect": "Allow",
        "Action": [
          "elasticloadbalancing:AddTags",
          "elasticloadbalancing:RemoveTags"
        ],
        "Resource": [
          "arn:aws:elasticloadbalancing:*:*:listener/net/*/*/*",
          "arn:aws:elasticloadbalancing:*:*:listener/app/*/*/*",
          "arn:aws:elasticloadbalancing:*:*:listener-rule/net/*/*/*",
          "arn:aws:elasticloadbalancing:*:*:listener-rule/app/*/*/*"
        ]
      },
      {
        "Effect": "Allow",
        "Action": [
          "elasticloadbalancing:ModifyLoadBalancerAttributes",
          "elasticloadbalancing:SetIpAddressType",
          "elasticloadbalancing:SetSecurityGroups",
          "elasticloadbalancing:SetSubnets",
          "elasticloadbalancing:DeleteLoadBalancer",
          "elasticloadbalancing:ModifyTargetGroup",
          "elasticloadbalancing:ModifyTargetGroupAttributes",
          "elasticloadbalancing:DeleteTargetGroup"
        ],
        "Resource": "*",
        "Condition": {
          "Null": {
            "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
          }
        }
      },
      {
        "Effect": "Allow",
        "Action": [
          "elasticloadbalancing:AddTags"
        ],
        "Resource": [
          "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
          "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
          "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*"
        ],
        "Condition": {
          "StringEquals": {
            "elasticloadbalancing:CreateAction": [
              "CreateTargetGroup",
              "CreateLoadBalancer"
            ]
          },
          "Null": {
            "aws:RequestTag/elbv2.k8s.aws/cluster": "false"
          }
        }
      },
      {
        "Effect": "Allow",
        "Action": [
          "elasticloadbalancing:RegisterTargets",
          "elasticloadbalancing:DeregisterTargets"
        ],
        "Resource": "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*"
      },
      {
        "Effect": "Allow",
        "Action": [
          "elasticloadbalancing:SetWebAcl",
          "elasticloadbalancing:ModifyListener",
          "elasticloadbalancing:AddListenerCertificates",
          "elasticloadbalancing:RemoveListenerCertificates",
          "elasticloadbalancing:ModifyRule"
        ],
        "Resource": "*"
      }
    ]
}
POLICY
}

resource "helm_release" "aws_lbc" {
  count      = var.create_lbc ? 1 : 0
  name       = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
  chart      = "aws-load-balancer-controller"
  namespace  = "kube-system"
  version    = var.aws_lbc_helm_chart_version
  values = [
    <<-EOT
          serviceAccount:
            create: true
            name: ${var.aws_lbc_sa}
            annotations: 
              eks.amazonaws.com/role-arn: ${aws_iam_role.aws_lbc[0].arn}

          rbac:
            create: true

          enableServiceMutatorWebhook: false
          region: ${var.AWS_DEFAULT_REGION}
          vpcId: ${aws_vpc.aws-vpc.id}
          clusterName: ${aws_eks_cluster.eks.name}
      EOT
  ]
  depends_on = [
    aws_eks_cluster.eks,
    aws_eks_node_group.general
  ]
}

# ArgoCD
resource "helm_release" "argocd" {
  count            = var.create_argocd ? 1 : 0
  name             = "argocd"
  repository       = "https://argoproj.github.io/argo-helm"
  chart            = "argo-cd"
  namespace        = "argocd"
  create_namespace = true
  version          = var.argocd_helm_chart_version
  values = [
    <<-EOT
          global:
            domain: ${var.argocd_hostname}

          configs:
            params:
              server.insecure: true

          server:
            ingress:
              enabled: true
              controller: aws
              ingressClassName: alb
              annotations:
                alb.ingress.kubernetes.io/scheme: internet-facing
                alb.ingress.kubernetes.io/target-type: ip
                alb.ingress.kubernetes.io/backend-protocol: HTTP
                alb.ingress.kubernetes.io/listen-ports: '[{"HTTPS":80}, {"HTTPS":443}]'
                alb.ingress.kubernetes.io/ssl-redirect: '443'
                alb.ingress.kubernetes.io/load-balancer-name: ${var.argocd_lb_name}
                alb.ingress.kubernetes.io/certificate-arn: arn:aws:acm:${var.AWS_DEFAULT_REGION}:${data.aws_caller_identity.current.account_id}:certificate/${var.argocd_certificate}
              aws:
                serviceType: ClusterIP
                backendProtocolVersion: GRPC
      EOT
  ]
  depends_on = [
    helm_release.aws_lbc
  ]
}

resource "kubernetes_secret_v1" "repo_1_connect_ssh_key" {
  count = var.create_repo_1_connection_key_secret ? 1 : 0
  metadata {
    name      = var.repo_1_name
    namespace = "argocd"
    labels = {
      "argocd.argoproj.io/secret-type" = "repository"
    }
  }
  data = {
    type          = "git"
    url           = var.repo_1_url
    sshPrivateKey = base64decode(var.repo_1_ssh_key)
  }
}

resource "kubernetes_secret_v1" "repo_2_connect_ssh_key" {
  count = var.create_repo_2_connection_key_secret ? 1 : 0
  metadata {
    name      = var.repo_2_name
    namespace = "argocd"
    labels = {
      "argocd.argoproj.io/secret-type" = "repository"
    }
  }
  data = {
    type          = "git"
    url           = var.repo_2_url
    sshPrivateKey = base64decode(var.repo_2_ssh_key)
  }
}

resource "time_sleep" "wait_10_minutes" {
  destroy_duration = "10m"
  depends_on       = [helm_release.argocd]
}

data "kubernetes_ingress_v1" "argocd_ingress" {
  count = var.deploy_data_kubernetes_ingress_v1_argocd_ingress ? 1 : 0
  metadata {
    name      = "argocd-server"
    namespace = "argocd"
  }
}

resource "null_resource" "extract_elb_hosted_zone_id" {
  count = var.deploy_terraform_data_elb_hosted_zone_id ? 1 : 0
  provisioner "local-exec" {
    command = "/bin/bash ${var.script_elb_hosted_zone_id} ${var.argocd_lb_name} ${var.local_file_elb_hosted_zone_id}"
  }
}

data "local_file" "elb_hosted_zone_id" {
  count = var.deploy_local_file_elb_hosted_zone_id ? 1 : 0
  filename = "${var.local_file_elb_hosted_zone_id}"
  depends_on  = [
    null_resource.extract_elb_hosted_zone_id
  ]
}

resource "aws_route53_record" "argoce_record" {
  count = var.deploy_argocd_route53_record ? 1 : 0
  zone_id = "${var.hosted_zone_id}"
  name    = "${var.argocd_hostname}"
  type    = "A"
  alias {
    name                   = data.kubernetes_ingress_v1.argocd_ingress[0].status.0.load_balancer.0.ingress.0.hostname
    zone_id                = element(split("\n", data.local_file.elb_hosted_zone_id[0].content), 0)
    evaluate_target_health = true
  }
  depends_on = [
    null_resource.extract_elb_hosted_zone_id
  ]
}
