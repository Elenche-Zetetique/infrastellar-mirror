# Infrastellar

## Overview
**Infrastellar** is a configuration repository for managing [ArgoCD](https://argo-cd.readthedocs.io/) applications and projects. It defines the sources of Git repositories and sets project scopes, ensuring a structured and maintainable deployment process for Kubernetes environments.

## Features
- Defines ArgoCD applications and projects.
- Manages Git repository sources for Helm charts and Kubernetes manifests.
- Specifies project scopes, including allowed repositories and cluster permissions.
- Ensures consistency across deployments with version-controlled configurations.

## Prerequisites
Ensure you have the following:
- Git repository for storing configurations

## Installation

1. Clone the repository:
```sh
 git clone https://github.com/your-org/infrastellar.git
 cd infrastellar
```

2. Apply changes and push to your repository.

3. GitLab-CI pipeline is triggered.

4. Trigger manually validation, plan and apply stages.

## Example Configuration
### ArgoCD Application
```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: NAME
  namespace: argocd
  finalizers:
  - resources-finalizer.argocd.argoproj.io
spec:
  project: dev # prod or test
  source:
    repoURL: git@gitlab.com:PATH_TO/REPO.git
    targetRevision: main
    path: PATH
    helm:
      values: |
        ingress:
          class: alb
  destination:
    server: https://kubernetes.default.svc
    namespace: NAMESPACE
  syncPolicy:
    automated: 
      prune: true
      selfHeal: true 
    syncOptions:
    - CreateNamespace=true
```

## License
This project is licensed under the [**Creative Commons Attribution-NonCommercial 4.0 (CC BY-NC 4.0)**](https://creativecommons.org/licenses/by-nc/4.0/legalcode.en) license.

### Summary:
- You are **free to use, modify, and share** this software **for non-commercial purposes**.
- **Commercial use is strictly prohibited**.
- No warranties or liability: The author is **not responsible** for any issues arising from use.

## Authors
Maintained by **Elenche Zetetique**.