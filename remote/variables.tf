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
  default     = false
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

variable "local_file_elb_hosted_zone_id" {
  description = "Name of the local file to save a Hosted Zone ID of ArgoCD Load Balancer"
  type        = string
}

variable "deploy_logstash" {
  description = "Flag to deploy Logstash"
  type        = bool
  default     = false
}

variable "deploy_filebeat" {
  description = "Flag to deploy Filebeat"
  type        = bool
  default     = false
}

variable "deploy_elasticsearch" {
  description = "Flag to deploy Elasticsearch"
  type        = bool
  default     = false
}

variable "deploy_kibana" {
  description = "Flag to deploy Kibana"
  type        = bool
  default     = false
}

