# ARPGuard Production Environment Setup Guide

## Overview

This guide provides step-by-step instructions for setting up ARPGuard in a production environment using AWS/Azure, Kubernetes, monitoring, and backup systems.

## Table of Contents

1. [Cloud Infrastructure Setup](#cloud-infrastructure-setup)
2. [Kubernetes Cluster Configuration](#kubernetes-cluster-configuration)
3. [Monitoring Stack Setup](#monitoring-stack-setup)
4. [Backup System Configuration](#backup-system-configuration)
5. [Security Considerations](#security-considerations)
6. [High Availability Setup](#high-availability-setup)

## Cloud Infrastructure Setup

### AWS Setup

1. **VPC Configuration**
   ```bash
   # Create VPC
   aws ec2 create-vpc --cidr-block 10.0.0.0/16 --tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=arpguard-vpc}]'

   # Create subnets
   aws ec2 create-subnet --vpc-id vpc-xxxxxx --cidr-block 10.0.1.0/24 --availability-zone us-east-1a
   aws ec2 create-subnet --vpc-id vpc-xxxxxx --cidr-block 10.0.2.0/24 --availability-zone us-east-1b
   ```

2. **Security Groups**
   ```bash
   # Create security group
   aws ec2 create-security-group --group-name arpguard-sg --description "ARPGuard Security Group" --vpc-id vpc-xxxxxx

   # Add inbound rules
   aws ec2 authorize-security-group-ingress --group-id sg-xxxxxx --protocol tcp --port 8080 --cidr 0.0.0.0/0
   aws ec2 authorize-security-group-ingress --group-id sg-xxxxxx --protocol tcp --port 443 --cidr 0.0.0.0/0
   ```

3. **IAM Roles**
   ```bash
   # Create IAM role for ARPGuard
   aws iam create-role --role-name arpguard-role --assume-role-policy-document file://trust-policy.json

   # Attach necessary policies
   aws iam attach-role-policy --role-name arpguard-role --policy-arn arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess
   ```

### Azure Setup

1. **Resource Group and Network**
   ```bash
   # Create resource group
   az group create --name arpguard-rg --location eastus

   # Create virtual network
   az network vnet create --name arpguard-vnet --resource-group arpguard-rg --address-prefix 10.0.0.0/16

   # Create subnets
   az network vnet subnet create --name arpguard-subnet1 --vnet-name arpguard-vnet --resource-group arpguard-rg --address-prefix 10.0.1.0/24
   az network vnet subnet create --name arpguard-subnet2 --vnet-name arpguard-vnet --resource-group arpguard-rg --address-prefix 10.0.2.0/24
   ```

2. **Network Security Groups**
   ```bash
   # Create NSG
   az network nsg create --name arpguard-nsg --resource-group arpguard-rg

   # Add inbound rules
   az network nsg rule create --name arpguard-http --nsg-name arpguard-nsg --resource-group arpguard-rg --priority 100 --access Allow --protocol Tcp --direction Inbound --source-address-prefixes '*' --source-port-ranges '*' --destination-address-prefixes '*' --destination-port-ranges 8080 443
   ```

## Kubernetes Cluster Configuration

### EKS Setup (AWS)

1. **Create EKS Cluster**
   ```bash
   # Create EKS cluster
   eksctl create cluster \
     --name arpguard-cluster \
     --region us-east-1 \
     --node-type t3.medium \
     --nodes 3 \
     --nodes-min 3 \
     --nodes-max 5 \
     --managed
   ```

2. **Configure ARPGuard Deployment**
   ```yaml
   # arpguard-deployment.yaml
   apiVersion: apps/v1
   kind: Deployment
   metadata:
     name: arpguard
     namespace: arpguard
   spec:
     replicas: 3
     selector:
       matchLabels:
         app: arpguard
     template:
       metadata:
         labels:
           app: arpguard
       spec:
         containers:
         - name: arpguard
           image: arpguard/arpguard:latest
           ports:
           - containerPort: 8080
           env:
           - name: ARPGUARD_API_KEY
             valueFrom:
               secretKeyRef:
                 name: arpguard-secrets
                 key: api-key
           resources:
             requests:
               cpu: "500m"
               memory: "1Gi"
             limits:
               cpu: "1000m"
               memory: "2Gi"
   ```

3. **Configure Service**
   ```yaml
   # arpguard-service.yaml
   apiVersion: v1
   kind: Service
   metadata:
     name: arpguard-service
     namespace: arpguard
   spec:
     selector:
       app: arpguard
     ports:
     - port: 8080
       targetPort: 8080
     type: LoadBalancer
   ```

### AKS Setup (Azure)

1. **Create AKS Cluster**
   ```bash
   # Create AKS cluster
   az aks create \
     --resource-group arpguard-rg \
     --name arpguard-cluster \
     --node-count 3 \
     --enable-addons monitoring \
     --generate-ssh-keys
   ```

2. **Configure ARPGuard Deployment**
   ```yaml
   # arpguard-deployment.yaml
   apiVersion: apps/v1
   kind: Deployment
   metadata:
     name: arpguard
     namespace: arpguard
   spec:
     replicas: 3
     selector:
       matchLabels:
         app: arpguard
     template:
       metadata:
         labels:
           app: arpguard
       spec:
         containers:
         - name: arpguard
           image: arpguard/arpguard:latest
           ports:
           - containerPort: 8080
           env:
           - name: ARPGUARD_API_KEY
             valueFrom:
               secretKeyRef:
                 name: arpguard-secrets
                 key: api-key
           resources:
             requests:
               cpu: "500m"
               memory: "1Gi"
             limits:
               cpu: "1000m"
               memory: "2Gi"
   ```

## Monitoring Stack Setup

### Prometheus and Grafana Setup

1. **Install Prometheus**
   ```bash
   # Create Prometheus namespace
   kubectl create namespace monitoring

   # Install Prometheus using Helm
   helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
   helm install prometheus prometheus-community/kube-prometheus-stack -n monitoring
   ```

2. **Configure ARPGuard Metrics**
   ```yaml
   # arpguard-metrics.yaml
   apiVersion: monitoring.coreos.com/v1
   kind: ServiceMonitor
   metadata:
     name: arpguard-metrics
     namespace: arpguard
   spec:
     selector:
       matchLabels:
         app: arpguard
     endpoints:
     - port: metrics
       interval: 15s
   ```

3. **Configure Grafana Dashboards**
   ```bash
   # Import ARPGuard dashboard
   kubectl apply -f arpguard-dashboard.yaml
   ```

### Logging Setup

1. **Install ELK Stack**
   ```bash
   # Install Elasticsearch
   helm install elasticsearch elastic/elasticsearch -n logging

   # Install Kibana
   helm install kibana elastic/kibana -n logging

   # Install Filebeat
   helm install filebeat elastic/filebeat -n logging
   ```

2. **Configure Log Collection**
   ```yaml
   # arpguard-logging.yaml
   apiVersion: logging.banzaicloud.io/v1beta1
   kind: Flow
   metadata:
     name: arpguard-logs
     namespace: arpguard
   spec:
     filters:
     - parser:
         remove_key_name_field: true
         parse:
           type: json
     match:
     - select:
         labels:
           app: arpguard
     localOutputRefs:
     - arpguard-logs
   ```

## Backup System Configuration

### AWS Backup Setup

1. **Configure Backup Plan**
   ```bash
   # Create backup vault
   aws backup create-backup-vault --backup-vault-name arpguard-backup-vault

   # Create backup plan
   aws backup create-backup-plan --backup-plan file://backup-plan.json
   ```

2. **Configure Backup Selection**
   ```json
   {
     "SelectionName": "arpguard-backup-selection",
     "IamRoleArn": "arn:aws:iam::123456789012:role/service-role/AWSBackupDefaultServiceRole",
     "Resources": [
       "arn:aws:ec2:us-east-1:123456789012:volume/vol-1234567890abcdef0"
     ]
   }
   ```

### Azure Backup Setup

1. **Configure Recovery Services Vault**
   ```bash
   # Create Recovery Services Vault
   az backup vault create --name arpguard-vault --resource-group arpguard-rg --location eastus

   # Create backup policy
   az backup policy create --name arpguard-policy --vault-name arpguard-vault --resource-group arpguard-rg --policy file://backup-policy.json
   ```

2. **Configure Backup**
   ```bash
   # Enable backup for VM
   az backup protection enable-for-vm --resource-group arpguard-rg --vault-name arpguard-vault --vm arpguard-vm --policy-name arpguard-policy
   ```

## Security Considerations

1. **Network Security**
   - Implement network policies
   - Configure TLS/SSL
   - Set up WAF rules

2. **Access Control**
   - Implement RBAC
   - Configure IAM roles
   - Set up MFA

3. **Data Protection**
   - Enable encryption at rest
   - Configure encryption in transit
   - Implement key management

## High Availability Setup

1. **Multi-AZ Deployment**
   - Deploy across multiple availability zones
   - Configure auto-scaling
   - Set up load balancing

2. **Disaster Recovery**
   - Configure cross-region replication
   - Set up failover procedures
   - Document recovery procedures

## Next Steps

1. Deploy the infrastructure using the provided configurations
2. Configure monitoring and alerting
3. Set up backup and recovery procedures
4. Perform security hardening
5. Conduct load testing
6. Document operational procedures 