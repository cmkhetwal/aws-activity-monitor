#!/usr/bin/env python3
"""
AWS Security Monitor - Real-time Change Detection and Alerting
Monitors critical AWS resources across multiple accounts and regions
"""

import boto3
import json
import os
import pickle
import logging
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from typing import Dict, List, Any, Optional
import configparser
from pathlib import Path

# Configure logging
LOG_DIR = Path.home() / '.aws-security-monitor'
LOG_DIR.mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.DEBUG if os.getenv('DEBUG') else logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / 'aws_security_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('AWSSecurityMonitor')

# State file to track processed events
STATE_DIR = Path.home() / '.aws-security-monitor'
STATE_DIR.mkdir(exist_ok=True)
STATE_FILE = STATE_DIR / 'processed_events.pkl'

# Critical event names to monitor
CRITICAL_EVENTS = {
    # IAM Events
    'CreateUser', 'DeleteUser', 'UpdateUser',
    'CreateRole', 'DeleteRole', 'UpdateRole', 'AttachRolePolicy', 'DetachRolePolicy',
    'CreatePolicy', 'DeletePolicy', 'CreatePolicyVersion', 'DeletePolicyVersion',
    'CreateAccessKey', 'DeleteAccessKey', 'UpdateAccessKey',
    'CreateGroup', 'DeleteGroup', 'AddUserToGroup', 'RemoveUserFromGroup',
    'PutRolePolicy', 'DeleteRolePolicy', 'PutUserPolicy', 'DeleteUserPolicy',
    'CreateLoginProfile', 'UpdateLoginProfile', 'DeleteLoginProfile',
    'EnableMFADevice', 'DeactivateMFADevice', 'DeleteVirtualMFADevice',
    'UpdateAccountPasswordPolicy', 'CreateServiceLinkedRole',
    'AssumeRole', 'AssumeRoleWithSAML', 'AssumeRoleWithWebIdentity',
    
    # EC2 Events
    'RunInstances', 'TerminateInstances', 'StopInstances', 'StartInstances',
    'ModifyInstanceAttribute', 'ModifyInstanceMetadataOptions',
    'CreateSecurityGroup', 'DeleteSecurityGroup', 'ModifySecurityGroupRules',
    'AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress',
    'RevokeSecurityGroupIngress', 'RevokeSecurityGroupEgress',
    'UpdateSecurityGroupRuleDescriptionsIngress', 'UpdateSecurityGroupRuleDescriptionsEgress',
    'CreateVolume', 'DeleteVolume', 'AttachVolume', 'DetachVolume',
    'CreateSnapshot', 'DeleteSnapshot', 'ModifySnapshotAttribute',
    'CreateImage', 'DeregisterImage', 'ModifyImageAttribute',
    'AllocateAddress', 'ReleaseAddress', 'AssociateAddress', 'DisassociateAddress',
    'CreateKeyPair', 'DeleteKeyPair', 'ImportKeyPair',
    'AssociateIamInstanceProfile', 'DisassociateIamInstanceProfile',
    
    # VPC & Networking
    'CreateVpc', 'DeleteVpc', 'ModifyVpcAttribute',
    'CreateSubnet', 'DeleteSubnet', 'ModifySubnetAttribute',
    'CreateRouteTable', 'DeleteRouteTable', 'CreateRoute', 'DeleteRoute',
    'CreateInternetGateway', 'DeleteInternetGateway', 'AttachInternetGateway',
    'CreateNatGateway', 'DeleteNatGateway',
    'CreateVpcPeeringConnection', 'AcceptVpcPeeringConnection', 'DeleteVpcPeeringConnection',
    'CreateTransitGateway', 'DeleteTransitGateway', 'ModifyTransitGateway',
    'CreateVpnConnection', 'DeleteVpnConnection',
    'CreateCustomerGateway', 'DeleteCustomerGateway',
    'CreateNetworkAcl', 'DeleteNetworkAcl', 'CreateNetworkAclEntry', 'DeleteNetworkAclEntry',
    
    # S3 Events
    'CreateBucket', 'DeleteBucket', 'PutBucketPolicy', 'DeleteBucketPolicy',
    'PutBucketAcl', 'PutObjectAcl', 'PutBucketVersioning',
    'PutBucketEncryption', 'DeleteBucketEncryption',
    'PutBucketPublicAccessBlock', 'DeleteBucketPublicAccessBlock',
    'PutBucketLogging', 'PutBucketReplication', 'DeleteBucketReplication',
    'PutBucketLifecycle', 'DeleteBucketLifecycle',
    'PutBucketCors', 'DeleteBucketCors',
    'PutBucketWebsite', 'DeleteBucketWebsite',
    'DeleteObject', 'DeleteObjectVersion',
    
    # Lambda Events
    'CreateFunction', 'DeleteFunction', 'UpdateFunctionCode', 'UpdateFunctionConfiguration',
    'AddPermission', 'RemovePermission', 'PutFunctionConcurrency',
    'CreateEventSourceMapping', 'DeleteEventSourceMapping', 'UpdateEventSourceMapping',
    'TagResource', 'UntagResource', 'PutFunctionEventInvokeConfig',
    'CreateAlias', 'DeleteAlias', 'UpdateAlias',
    
    # RDS Events
    'CreateDBInstance', 'DeleteDBInstance', 'ModifyDBInstance',
    'CreateDBCluster', 'DeleteDBCluster', 'ModifyDBCluster',
    'CreateDBSnapshot', 'DeleteDBSnapshot', 'ModifyDBSnapshotAttribute',
    'CreateDBClusterSnapshot', 'DeleteDBClusterSnapshot',
    'RestoreDBInstanceFromDBSnapshot', 'RestoreDBClusterFromSnapshot',
    'CreateDBParameterGroup', 'DeleteDBParameterGroup', 'ModifyDBParameterGroup',
    'CreateDBSubnetGroup', 'DeleteDBSubnetGroup', 'ModifyDBSubnetGroup',
    'CreateDBSecurityGroup', 'DeleteDBSecurityGroup',
    'AuthorizeDBSecurityGroupIngress', 'RevokeDBSecurityGroupIngress',
    'CreateDBProxy', 'DeleteDBProxy', 'ModifyDBProxy',
    
    # CloudTrail Events
    'CreateTrail', 'DeleteTrail', 'UpdateTrail', 'StartLogging', 'StopLogging',
    'PutEventSelectors', 'PutInsightSelectors',
    
    
    # Secrets Manager
    'CreateSecret', 'DeleteSecret', 'UpdateSecret', 'RestoreSecret',
    'GetSecretValue', 'PutSecretValue', 'UpdateSecretVersionStage',
    'RotateSecret', 'CancelRotateSecret',
    
    # SSM Events
    'SendCommand', 'CreateDocument', 'UpdateDocument', 'DeleteDocument',
    'PutParameter', 'DeleteParameter', 'DeleteParameters',
    'CreateMaintenanceWindow', 'UpdateMaintenanceWindow', 'DeleteMaintenanceWindow',
    'CreatePatchBaseline', 'UpdatePatchBaseline', 'DeletePatchBaseline',
    'RegisterTargetWithMaintenanceWindow', 'DeregisterTargetFromMaintenanceWindow',
    'StartSession', 'TerminateSession', 'ResumeSession',
    'CreateActivation', 'DeleteActivation',
    'RegisterManagedInstance', 'DeregisterManagedInstance',
    
    # CloudFront Events
    'CreateDistribution', 'UpdateDistribution', 'DeleteDistribution',
    'CreateOriginAccessIdentity', 'UpdateOriginAccessIdentity', 'DeleteOriginAccessIdentity',
    'CreateInvalidation', 'CreateFieldLevelEncryptionConfig', 'DeleteFieldLevelEncryptionConfig',
    'AssociateAlias', 'UpdateCloudFrontOriginAccessIdentity',
    
    # ACM Events
    'RequestCertificate', 'DeleteCertificate', 'ImportCertificate',
    'RemoveTagsFromCertificate', 'AddTagsToCertificate',
    'UpdateCertificateOptions', 'ResendValidationEmail',
    
    # Load Balancer Events
    'CreateLoadBalancer', 'DeleteLoadBalancer', 'ModifyLoadBalancerAttributes',
    'CreateTargetGroup', 'DeleteTargetGroup', 'ModifyTargetGroup',
    'CreateListener', 'DeleteListener', 'ModifyListener',
    'CreateRule', 'DeleteRule', 'ModifyRule',
    'RegisterTargets', 'DeregisterTargets',
    
    # ECS/EKS Events
    'CreateCluster', 'DeleteCluster', 'UpdateCluster',
    'CreateService', 'DeleteService', 'UpdateService',
    'CreateTaskDefinition', 'DeregisterTaskDefinition',
    'RunTask', 'StartTask', 'StopTask',
    'CreateNodegroup', 'DeleteNodegroup', 'UpdateNodegroupConfig',
    
    # Organizations & Account
    'CreateOrganization', 'DeleteOrganization',
    'CreateAccount', 'CloseAccount', 'InviteAccountToOrganization',
    'CreatePolicy', 'DeletePolicy', 'AttachPolicy', 'DetachPolicy',
    'EnablePolicyType', 'DisablePolicyType',
    'CreateOrganizationalUnit', 'DeleteOrganizationalUnit',
    
    # Config & Compliance
    'PutConfigRule', 'DeleteConfigRule', 'PutConfigurationRecorder',
    'StartConfigurationRecorder', 'StopConfigurationRecorder',
    'PutDeliveryChannel', 'DeleteDeliveryChannel',
    
    # GuardDuty & Security Hub
    'CreateDetector', 'DeleteDetector', 'UpdateDetector',
    'CreateIPSet', 'DeleteIPSet', 'UpdateIPSet',
    'CreateThreatIntelSet', 'DeleteThreatIntelSet',
    'EnableSecurityHub', 'DisableSecurityHub',
    
    # WAF Events
    'CreateWebACL', 'DeleteWebACL', 'UpdateWebACL',
    'CreateRule', 'DeleteRule', 'UpdateRule',
    'CreateIPSet', 'DeleteIPSet', 'UpdateIPSet',
    
    # DynamoDB Events
    'CreateTable', 'DeleteTable', 'UpdateTable',
    'CreateBackup', 'DeleteBackup', 'RestoreTableFromBackup',
    'UpdateContinuousBackups', 'UpdateTimeToLive',
    'CreateGlobalTable', 'UpdateGlobalTable',
    
    # API Gateway Events
    'CreateRestApi', 'DeleteRestApi', 'UpdateRestApi',
    'CreateDeployment', 'DeleteDeployment',
    'CreateStage', 'DeleteStage', 'UpdateStage',
    'CreateApiKey', 'DeleteApiKey', 'UpdateApiKey',
    'CreateUsagePlan', 'DeleteUsagePlan', 'UpdateUsagePlan',
    
    # EventBridge/CloudWatch Events
    'PutRule', 'DeleteRule', 'EnableRule', 'DisableRule',
    'PutTargets', 'RemoveTargets',
    'CreateEventBus', 'DeleteEventBus',
    
    # SNS/SQS Events
    'CreateTopic', 'DeleteTopic', 'Subscribe', 'Unsubscribe',
    'CreateQueue', 'DeleteQueue', 'SetQueueAttributes',
    'AddPermission', 'RemovePermission',
}

# Events to explicitly ignore (read-only operations)
IGNORED_EVENTS = {
    'Get', 'List', 'Describe', 'Head', 'Select', 'Search', 'Lookup', 'View', 'Read',
    'ConsoleLogin', 'CheckMfa', 'Decode', 'Verify', 'AssumeRole',
    'GenerateCredentialReport', 'GetCredentialReport', 'GetAccountSummary',
    'GetLoginProfile', 'GetRole', 'GetUser', 'GetPolicy',
    'TestConnection', 'ValidatePipelineDefinition', 'GenerateDataKey',
    'Decrypt', 'Encrypt'
}


class AWSSecurityMonitor:
    def __init__(self):
        self.profiles = self._get_aws_profiles()
        self.processed_events = self._load_state()
        self.events_to_notify = defaultdict(lambda: defaultdict(list))
        
    def _get_aws_profiles(self) -> List[str]:
        """Get all AWS profiles from credentials file"""
        credentials_path = Path.home() / '.aws' / 'credentials'
        if not credentials_path.exists():
            logger.error(f"AWS credentials file not found at {credentials_path}")
            return ['default']
        
        config = configparser.ConfigParser()
        config.read(credentials_path)
        profiles = [section for section in config.sections()]
        logger.info(f"Found AWS profiles: {profiles}")
        return profiles if profiles else ['default']
    
    def _load_state(self) -> set:
        """Load previously processed events"""
        if STATE_FILE.exists():
            try:
                with open(STATE_FILE, 'rb') as f:
                    return pickle.load(f)
            except Exception as e:
                logger.warning(f"Could not load state file: {e}")
        return set()
    
    def _save_state(self):
        """Save processed events to prevent duplicate alerts"""
        try:
            with open(STATE_FILE, 'wb') as f:
                pickle.dump(self.processed_events, f)
        except Exception as e:
            logger.error(f"Could not save state file: {e}")
    
    def _should_monitor_event(self, event_name: str) -> bool:
        """Check if event should be monitored"""
        # Skip if it's a read-only operation
        for ignored in IGNORED_EVENTS:
            if event_name.startswith(ignored):
                return False
        
        # Skip KMS events completely
        if 'kms' in event_name.lower() or event_name.startswith('KMS'):
            return False
            
        # Always monitor security group events (but not describe/get operations)
        if 'SecurityGroup' in event_name and any(action in event_name for action in 
            ['Create', 'Delete', 'Authorize', 'Revoke', 'Modify', 'Update']):
            return True
        
        # Only monitor events that are actual changes (Create, Delete, Update, Modify, etc.)
        change_actions = ['Create', 'Delete', 'Update', 'Modify', 'Put', 'Add', 'Remove', 
                         'Attach', 'Detach', 'Enable', 'Disable', 'Start', 'Stop', 
                         'Terminate', 'Launch', 'Run', 'Authorize', 'Revoke']
        
        if not any(action in event_name for action in change_actions):
            return False
        
        # Check if it's in critical events list
        return event_name in CRITICAL_EVENTS
    
    def _is_system_generated_event(self, event_details: Dict) -> bool:
        """Check if event is system-generated (AWS service roles, automation, etc.)"""
        user_type = event_details.get('user_type', '')
        user_name = event_details.get('user_name', '')
        user_arn = event_details.get('user_arn', '')
        user_agent = event_details.get('user_agent', '')
        source_ip = event_details.get('source_ip', '')
        
        # Skip events from AWS service roles and automated processes
        system_indicators = [
            # AWS Service Roles
            'AWSServiceRole',
            'aws-elasticbeanstalk',
            'AWSBackup',
            'AWS-Backup',
            'AWSDataLifecycleManager',
            'AWSServiceRoleFor',
            'aws-controltower',
            'AWSControlTower',
            'aws-organizations',
            'AWSCloudFormation',
            'aws-cloudformation',
            'AWSLambda',
            'aws-lambda',
            'AWSGlue',
            'aws-glue',
            'AWSEC2Fleet',
            'AWSAutoScaling',
            'aws-autoscaling',
            'AWSBatch',
            'aws-batch',
            'AWSECS',
            'aws-ecs',
            'AWSEKS',
            'aws-eks',
            'AWSCodeBuild',
            'aws-codebuild',
            'AWSCodeDeploy',
            'aws-codedeploy',
            'AWSCodePipeline',
            'aws-codepipeline',
            'AWSServiceCatalog',
            'aws-service-catalog',
            'AWSSystems',
            'aws-systems-manager',
            'AWSConfig',
            'aws-config',
            'AWSSecurityHub',
            'aws-securityhub',
            'AWSGuardDuty',
            'aws-guardduty',
            'AWSSSO',
            'aws-sso',
            'AWSTrustedAdvisor',
            'aws-trusted-advisor',
            'AWSSupport',
            'aws-support',
            'AWSReplication',
            'aws-replication',
            'DataLifecycleManager',
            'AWS-DLM',
            'aws-dlm',
            'rds.amazonaws.com',
            'backup.amazonaws.com',
            'elasticbeanstalk.amazonaws.com',
            'cloudformation.amazonaws.com',
            'lambda.amazonaws.com',
            'autoscaling.amazonaws.com',
            'ecs.amazonaws.com',
            'eks.amazonaws.com',
            'sagemaker.amazonaws.com'
        ]
        
        # Check user identity for system patterns
        for indicator in system_indicators:
            if indicator.lower() in user_name.lower():
                return True
            if indicator.lower() in user_arn.lower():
                return True
        
        # Check if it's an AWS internal service based on user type
        if user_type in ['AWSService', 'AWSAccount']:
            return True
        
        # Check for AWS internal IPs and user agents
        aws_internal_patterns = [
            'aws-internal',
            'aws:internal',
            'amazonaws.com',
            'aws-sdk',
            'Boto3',
            'aws-cli',
            'console.aws.amazon.com',
            'signin.aws.amazon.com',
            'AWS Internal',
            'AWS-Internal'
        ]
        
        # Skip if source IP is from AWS internal services (commonly used by AWS services)
        if source_ip and any(pattern in source_ip for pattern in ['aws:', 'AWS Internal', 'amazonaws.com']):
            return True
            
        # Check user agent for AWS internal services
        for pattern in aws_internal_patterns:
            if pattern.lower() in user_agent.lower() and 'console' not in user_agent.lower():
                # Allow console access but skip SDK/CLI automated calls
                if any(x in user_agent.lower() for x in ['sdk', 'cli', 'boto']):
                    # Unless it's clearly a user action
                    if not any(human_pattern in event_details.get('event_name', '') 
                             for human_pattern in ['Console', 'Create', 'Delete', 'Modify']):
                        return True
        
        # Check for scheduled/automated backup operations
        if 'backup' in user_name.lower() or 'backup' in user_arn.lower():
            return True
            
        # Check for AWS managed rules and automated compliance
        if any(x in user_name.lower() for x in ['aws-controltower', 'aws-config-rule', 'aws-organizations']):
            return True
            
        return False
    
    def _extract_change_details(self, event_details: Dict) -> Dict[str, Any]:
        """Extract detailed change information from CloudTrail event"""
        event_name = event_details.get('event_name', '')
        request_params = event_details.get('request_parameters', {})
        response_elements = event_details.get('response_elements', {})
        
        change_info = {
            'action_type': self._get_action_type(event_name),
            'changes': [],
            'summary': ''
        }
        
        # Security Group Changes
        if 'SecurityGroup' in event_name:
            change_info = self._parse_security_group_changes(event_name, request_params, response_elements)
        
        # EC2 Instance Changes
        elif event_name in ['ModifyInstanceAttribute', 'RunInstances', 'TerminateInstances', 'StopInstances', 'StartInstances']:
            change_info = self._parse_ec2_changes(event_name, request_params, response_elements)
        
        # IAM Changes
        elif any(iam_action in event_name for iam_action in ['CreateUser', 'DeleteUser', 'CreateRole', 'DeleteRole', 'AttachPolicy', 'DetachPolicy', 'PutPolicy']):
            change_info = self._parse_iam_changes(event_name, request_params, response_elements)
        
        # S3 Changes
        elif any(s3_action in event_name for s3_action in ['PutBucketPolicy', 'DeleteBucketPolicy', 'PutBucketAcl', 'PutBucketEncryption']):
            change_info = self._parse_s3_changes(event_name, request_params, response_elements)
        
        # RDS Changes
        elif any(rds_action in event_name for rds_action in ['ModifyDBInstance', 'CreateDBInstance', 'DeleteDBInstance']):
            change_info = self._parse_rds_changes(event_name, request_params, response_elements)
        
        # Lambda Changes
        elif any(lambda_action in event_name for lambda_action in ['UpdateFunctionCode', 'UpdateFunctionConfiguration', 'AddPermission', 'RemovePermission']):
            change_info = self._parse_lambda_changes(event_name, request_params, response_elements)
        
        # SSM Changes
        elif event_name in ['StartSession', 'SendCommand', 'PutParameter', 'DeleteParameter']:
            change_info = self._parse_ssm_changes(event_name, request_params, response_elements)
        
        # Generic change parsing for other services
        else:
            change_info = self._parse_generic_changes(event_name, request_params, response_elements)
        
        return change_info
    
    def _get_action_type(self, event_name: str) -> str:
        """Determine the type of action"""
        if any(x in event_name for x in ['Create', 'Add', 'Attach', 'Enable', 'Start', 'Launch', 'Run']):
            return 'CREATE'
        elif any(x in event_name for x in ['Delete', 'Remove', 'Detach', 'Disable', 'Stop', 'Terminate']):
            return 'DELETE'
        elif any(x in event_name for x in ['Modify', 'Update', 'Put', 'Change']):
            return 'MODIFY'
        elif any(x in event_name for x in ['Authorize', 'Revoke']):
            return 'PERMISSION'
        else:
            return 'OTHER'
    
    def _parse_security_group_changes(self, event_name: str, request_params: Dict, response_elements: Dict) -> Dict:
        """Parse security group changes in detail"""
        changes = []
        summary = ""
        
        if event_name == 'RevokeSecurityGroupIngress':
            # Parse revoked rules
            ip_permissions = request_params.get('ipPermissions', {}).get('items', [])
            revoked_rules = response_elements.get('revokedSecurityGroupRuleSet', {}).get('items', [])
            
            for rule in ip_permissions:
                protocol = rule.get('ipProtocol', 'unknown')
                from_port = rule.get('fromPort', 'any')
                to_port = rule.get('toPort', 'any')
                
                # Get source details
                sources = []
                ip_ranges = rule.get('ipRanges', {}).get('items', [])
                for ip_range in ip_ranges:
                    cidr = ip_range.get('cidrIp', '')
                    desc = ip_range.get('description', '')
                    sources.append(f"{cidr} ({desc})" if desc else cidr)
                
                port_range = f"{from_port}-{to_port}" if from_port != to_port else str(from_port)
                if from_port == 'any':
                    port_range = "All ports"
                
                changes.append({
                    'type': 'REMOVED',
                    'description': f"Inbound rule: {protocol.upper()}:{port_range} from {', '.join(sources)}",
                    'details': {
                        'protocol': protocol,
                        'ports': port_range,
                        'sources': sources
                    }
                })
            
            summary = f"Removed {len(changes)} inbound rule(s) from security group"
        
        elif event_name == 'AuthorizeSecurityGroupIngress':
            # Parse authorized rules
            ip_permissions = request_params.get('ipPermissions', {}).get('items', [])
            
            for rule in ip_permissions:
                protocol = rule.get('ipProtocol', 'unknown')
                from_port = rule.get('fromPort', 'any')
                to_port = rule.get('toPort', 'any')
                
                sources = []
                ip_ranges = rule.get('ipRanges', {}).get('items', [])
                for ip_range in ip_ranges:
                    cidr = ip_range.get('cidrIp', '')
                    desc = ip_range.get('description', '')
                    sources.append(f"{cidr} ({desc})" if desc else cidr)
                
                port_range = f"{from_port}-{to_port}" if from_port != to_port else str(from_port)
                if from_port == 'any':
                    port_range = "All ports"
                
                changes.append({
                    'type': 'ADDED',
                    'description': f"Inbound rule: {protocol.upper()}:{port_range} from {', '.join(sources)}",
                    'details': {
                        'protocol': protocol,
                        'ports': port_range,
                        'sources': sources
                    }
                })
            
            summary = f"Added {len(changes)} inbound rule(s) to security group"
        
        elif event_name in ['RevokeSecurityGroupEgress', 'AuthorizeSecurityGroupEgress']:
            # Similar logic for outbound rules
            is_revoke = 'Revoke' in event_name
            rule_type = 'REMOVED' if is_revoke else 'ADDED'
            direction = 'outbound'
            
            ip_permissions = request_params.get('ipPermissions', {}).get('items', [])
            for rule in ip_permissions:
                protocol = rule.get('ipProtocol', 'unknown')
                from_port = rule.get('fromPort', 'any')
                to_port = rule.get('toPort', 'any')
                
                destinations = []
                ip_ranges = rule.get('ipRanges', {}).get('items', [])
                for ip_range in ip_ranges:
                    cidr = ip_range.get('cidrIp', '')
                    desc = ip_range.get('description', '')
                    destinations.append(f"{cidr} ({desc})" if desc else cidr)
                
                port_range = f"{from_port}-{to_port}" if from_port != to_port else str(from_port)
                if from_port == 'any':
                    port_range = "All ports"
                
                changes.append({
                    'type': rule_type,
                    'description': f"Outbound rule: {protocol.upper()}:{port_range} to {', '.join(destinations)}",
                    'details': {
                        'protocol': protocol,
                        'ports': port_range,
                        'destinations': destinations
                    }
                })
            
            action = "Removed" if is_revoke else "Added"
            summary = f"{action} {len(changes)} {direction} rule(s) from security group"
        
        return {
            'action_type': 'PERMISSION',
            'changes': changes,
            'summary': summary
        }
    
    def _parse_ec2_changes(self, event_name: str, request_params: Dict, response_elements: Dict) -> Dict:
        """Parse EC2 instance changes"""
        changes = []
        summary = ""
        
        if event_name == 'ModifyInstanceAttribute':
            attribute = request_params.get('attribute', 'unknown')
            instance_id = request_params.get('instanceId', 'unknown')
            
            if attribute == 'instanceType':
                old_type = request_params.get('instanceType', {}).get('value', 'unknown')
                new_type = request_params.get('value', 'unknown')
                
                changes.append({
                    'type': 'MODIFIED',
                    'description': f"Instance type changed from {old_type} to {new_type}",
                    'details': {
                        'attribute': 'Instance Type',
                        'old_value': old_type,
                        'new_value': new_type
                    }
                })
                summary = f"Changed instance type for {instance_id}"
            
            elif attribute == 'sourceDestCheck':
                new_value = request_params.get('sourceDestCheck', {}).get('value', 'unknown')
                changes.append({
                    'type': 'MODIFIED',
                    'description': f"Source/Destination check set to: {new_value}",
                    'details': {
                        'attribute': 'Source/Dest Check',
                        'new_value': new_value
                    }
                })
                summary = f"Modified source/destination check for {instance_id}"
        
        elif event_name == 'RunInstances':
            instances = response_elements.get('instancesSet', {}).get('items', [])
            for instance in instances:
                instance_type = instance.get('instanceType', 'unknown')
                instance_id = instance.get('instanceId', 'unknown')
                image_id = instance.get('imageId', 'unknown')
                
                changes.append({
                    'type': 'CREATED',
                    'description': f"Launched instance {instance_id} ({instance_type}) from AMI {image_id}",
                    'details': {
                        'instance_id': instance_id,
                        'instance_type': instance_type,
                        'image_id': image_id
                    }
                })
            
            summary = f"Launched {len(instances)} EC2 instance(s)"
        
        elif event_name in ['TerminateInstances', 'StopInstances', 'StartInstances']:
            instances = request_params.get('instancesSet', {}).get('items', [])
            action = event_name.replace('Instances', '').lower()
            
            for instance in instances:
                instance_id = instance.get('instanceId', 'unknown')
                changes.append({
                    'type': 'MODIFIED',
                    'description': f"{action.capitalize()}ed instance {instance_id}",
                    'details': {
                        'instance_id': instance_id,
                        'action': action
                    }
                })
            
            summary = f"{action.capitalize()}ed {len(instances)} instance(s)"
        
        return {
            'action_type': self._get_action_type(event_name),
            'changes': changes,
            'summary': summary
        }
    
    def _parse_iam_changes(self, event_name: str, request_params: Dict, response_elements: Dict) -> Dict:
        """Parse IAM changes"""
        changes = []
        summary = ""
        
        if event_name in ['CreateUser', 'DeleteUser']:
            user_name = request_params.get('userName', 'unknown')
            action = 'Created' if 'Create' in event_name else 'Deleted'
            
            changes.append({
                'type': 'CREATED' if 'Create' in event_name else 'DELETED',
                'description': f"{action} IAM user: {user_name}",
                'details': {'user_name': user_name}
            })
            summary = f"{action} IAM user {user_name}"
        
        elif event_name in ['AttachUserPolicy', 'DetachUserPolicy']:
            user_name = request_params.get('userName', 'unknown')
            policy_arn = request_params.get('policyArn', 'unknown')
            action = 'Attached' if 'Attach' in event_name else 'Detached'
            
            changes.append({
                'type': 'MODIFIED',
                'description': f"{action} policy {policy_arn.split('/')[-1]} to/from user {user_name}",
                'details': {
                    'user_name': user_name,
                    'policy_arn': policy_arn,
                    'action': action.lower()
                }
            })
            summary = f"{action} policy to user {user_name}"
        
        return {
            'action_type': self._get_action_type(event_name),
            'changes': changes,
            'summary': summary
        }
    
    def _parse_s3_changes(self, event_name: str, request_params: Dict, response_elements: Dict) -> Dict:
        """Parse S3 changes"""
        changes = []
        summary = ""
        bucket = request_params.get('bucketName', 'unknown')
        
        if event_name == 'PutBucketPolicy':
            policy = request_params.get('policy', '')
            changes.append({
                'type': 'MODIFIED',
                'description': f"Updated bucket policy for {bucket}",
                'details': {
                    'bucket': bucket,
                    'policy_length': len(policy)
                }
            })
            summary = f"Modified bucket policy for {bucket}"
        
        elif event_name == 'PutBucketAcl':
            acl = request_params.get('accessControlPolicy', {})
            changes.append({
                'type': 'MODIFIED',
                'description': f"Updated ACL for bucket {bucket}",
                'details': {
                    'bucket': bucket,
                    'acl_grants': len(acl.get('accessControlList', {}).get('grant', []))
                }
            })
            summary = f"Modified ACL for bucket {bucket}"
        
        return {
            'action_type': self._get_action_type(event_name),
            'changes': changes,
            'summary': summary
        }
    
    def _parse_rds_changes(self, event_name: str, request_params: Dict, response_elements: Dict) -> Dict:
        """Parse RDS changes"""
        changes = []
        summary = ""
        db_instance = request_params.get('dBInstanceIdentifier', 'unknown')
        
        if event_name == 'ModifyDBInstance':
            # Check for instance class changes
            if 'dBInstanceClass' in request_params:
                new_class = request_params.get('dBInstanceClass')
                changes.append({
                    'type': 'MODIFIED',
                    'description': f"Changed DB instance class to {new_class}",
                    'details': {'db_instance': db_instance, 'new_class': new_class}
                })
            
            # Check for storage changes
            if 'allocatedStorage' in request_params:
                new_storage = request_params.get('allocatedStorage')
                changes.append({
                    'type': 'MODIFIED',
                    'description': f"Changed allocated storage to {new_storage} GB",
                    'details': {'db_instance': db_instance, 'new_storage': new_storage}
                })
            
            summary = f"Modified RDS instance {db_instance}"
        
        return {
            'action_type': self._get_action_type(event_name),
            'changes': changes,
            'summary': summary
        }
    
    def _parse_lambda_changes(self, event_name: str, request_params: Dict, response_elements: Dict) -> Dict:
        """Parse Lambda function changes"""
        changes = []
        summary = ""
        function_name = request_params.get('functionName', 'unknown')
        
        if event_name == 'UpdateFunctionCode':
            changes.append({
                'type': 'MODIFIED',
                'description': f"Updated function code for {function_name}",
                'details': {'function_name': function_name}
            })
            summary = f"Updated code for Lambda function {function_name}"
        
        elif event_name == 'UpdateFunctionConfiguration':
            # Check for runtime changes
            if 'runtime' in request_params:
                new_runtime = request_params.get('runtime')
                changes.append({
                    'type': 'MODIFIED',
                    'description': f"Changed runtime to {new_runtime}",
                    'details': {'function_name': function_name, 'new_runtime': new_runtime}
                })
            
            summary = f"Updated configuration for Lambda function {function_name}"
        
        return {
            'action_type': self._get_action_type(event_name),
            'changes': changes,
            'summary': summary
        }
    
    def _parse_ssm_changes(self, event_name: str, request_params: Dict, response_elements: Dict) -> Dict:
        """Parse SSM changes"""
        changes = []
        summary = ""
        
        if event_name == 'StartSession':
            target = request_params.get('target', 'unknown')
            session_id = response_elements.get('sessionId', 'unknown')
            
            changes.append({
                'type': 'CREATED',
                'description': f"Started SSM session to {target}",
                'details': {
                    'target': target,
                    'session_id': session_id
                }
            })
            summary = f"Started SSM session to {target}"
        
        elif event_name == 'PutParameter':
            name = request_params.get('name', 'unknown')
            param_type = request_params.get('type', 'unknown')
            
            changes.append({
                'type': 'MODIFIED',
                'description': f"Updated SSM parameter {name} (type: {param_type})",
                'details': {
                    'parameter_name': name,
                    'type': param_type
                }
            })
            summary = f"Updated SSM parameter {name}"
        
        return {
            'action_type': self._get_action_type(event_name),
            'changes': changes,
            'summary': summary
        }
    
    def _parse_generic_changes(self, event_name: str, request_params: Dict, response_elements: Dict) -> Dict:
        """Parse generic changes for any service"""
        changes = []
        summary = f"Performed {event_name} action"
        
        # Extract key identifiers from request parameters
        key_fields = ['name', 'id', 'arn', 'identifier', 'bucketName', 'groupName', 'userName', 'roleName']
        resource_identifier = 'unknown'
        
        for field in key_fields:
            if field in request_params:
                resource_identifier = request_params[field]
                break
        
        changes.append({
            'type': self._get_action_type(event_name),
            'description': f"{event_name} on {resource_identifier}",
            'details': {
                'resource': resource_identifier,
                'action': event_name
            }
        })
        
        return {
            'action_type': self._get_action_type(event_name),
            'changes': changes,
            'summary': summary
        }
    
    def _get_event_details(self, event: Dict, profile: str = 'default') -> Dict[str, Any]:
        """Extract relevant details from CloudTrail event"""
        # Handle both direct event dict and CloudTrail event wrapper
        if 'CloudTrailEvent' in event:
            # Parse the CloudTrailEvent JSON string
            import json
            trail_event = json.loads(event['CloudTrailEvent'])
        else:
            trail_event = event
            
        details = {
            'event_time': event.get('EventTime', trail_event.get('eventTime', '')),
            'event_name': event.get('EventName', trail_event.get('eventName', '')),
            'event_source': trail_event.get('eventSource', event.get('EventSource', '')),
            'aws_region': trail_event.get('awsRegion', event.get('AwsRegion', '')),
            'source_ip': trail_event.get('sourceIPAddress', event.get('SourceIPAddress', '')),
            'user_agent': trail_event.get('userAgent', event.get('UserAgent', '')),
            'error_code': trail_event.get('errorCode', event.get('ErrorCode', '')),
            'error_message': trail_event.get('errorMessage', event.get('ErrorMessage', '')),
            'request_parameters': trail_event.get('requestParameters', event.get('RequestParameters', {})),
            'response_elements': trail_event.get('responseElements', event.get('ResponseElements', {})),
            'resources': [],
            'profile': profile  # Store the profile for later use
        }
        
        # Extract user identity with better fallbacks
        user_identity = trail_event.get('userIdentity', event.get('UserIdentity', {}))
        details['user_type'] = user_identity.get('type', '')
        
        # Better user name extraction
        user_name = 'Unknown'
        if user_identity.get('userName'):
            user_name = user_identity.get('userName')
        elif user_identity.get('principalId'):
            principal_id = user_identity.get('principalId')
            if ':' in principal_id:
                user_name = principal_id.split(':')[-1]
            else:
                user_name = principal_id
        elif user_identity.get('arn'):
            arn = user_identity.get('arn')
            if '/' in arn:
                user_name = arn.split('/')[-1]
            elif ':' in arn:
                user_name = arn.split(':')[-1]
        elif user_identity.get('accountId'):
            user_name = f"Account-{user_identity.get('accountId')}"
        
        # Handle assumed role sessions
        session_context = user_identity.get('sessionContext', {})
        if session_context:
            session_issuer = session_context.get('sessionIssuer', {})
            if session_issuer.get('userName'):
                user_name = session_issuer.get('userName')
            elif session_issuer.get('arn'):
                arn = session_issuer.get('arn')
                if '/' in arn:
                    user_name = arn.split('/')[-1]
                    
        details['user_name'] = user_name
        details['user_arn'] = user_identity.get('arn', '')
        details['access_key_id'] = user_identity.get('accessKeyId', '')
        details['session_name'] = session_context.get('sessionIssuer', {}).get('userName', '')
        
        # Special handling for SSM StartSession events
        if details['event_name'] == 'StartSession':
            # Extract target instance from request parameters
            request_params = details.get('request_parameters', {})
            target = request_params.get('target', '')
            
            # SSM targets are usually in format i-xxxxx (instance id) or mi-xxxxx (managed instance)
            if target and target.startswith('i-'):
                # This is an EC2 instance
                instance_id = target
                profile = details.get('profile', 'default')
                region = details['aws_region']
                
                # Fetch EC2 instance details
                ec2_details = self._get_ec2_instance_details(instance_id, region, profile)
                if ec2_details:
                    # Add as a resource
                    resource_info = {
                        'type': 'AWS::EC2::Instance',
                        'name': instance_id,
                        'instance_name': ec2_details.get('instance_name', instance_id),
                        'instance_type': ec2_details.get('instance_type', 'Unknown'),
                        'private_ip': ec2_details.get('private_ip', 'N/A'),
                        'public_ip': ec2_details.get('public_ip', 'N/A'),
                        'state': ec2_details.get('state', 'Unknown'),
                        'arn': f"arn:aws:ec2:{region}:*:instance/{instance_id}"
                    }
                    details['resources'].append(resource_info)
                else:
                    # If we can't fetch details, at least add the instance ID
                    details['resources'].append({
                        'type': 'AWS::EC2::Instance',
                        'name': instance_id,
                        'instance_name': instance_id,
                        'arn': f"arn:aws:ec2:{region}:*:instance/{instance_id}"
                    })
                
                # Also store session details
                details['ssm_session_id'] = details.get('response_elements', {}).get('sessionId', '')
                details['ssm_target'] = target
        
        # Extract affected resources and enhance with additional details for EC2
        resources = event.get('Resources', trail_event.get('resources', []))
        for resource in resources:
            resource_info = {
                'type': resource.get('ResourceType', resource.get('resourceType', '')),
                'name': resource.get('ResourceName', resource.get('resourceName', '')),
                'arn': resource.get('ARN', resource.get('arn', ''))
            }
            
            # For EC2 instances, try to get additional details
            if resource_info['type'] == 'AWS::EC2::Instance':
                instance_id = resource_info['name']
                try:
                    # First try to get from CloudTrail response elements
                    response_elements = trail_event.get('responseElements', {})
                    if 'instancesSet' in response_elements:
                        instances = response_elements['instancesSet']['items']
                        for instance in instances:
                            if instance.get('instanceId') == instance_id:
                                # Get instance name from tags
                                instance_name = self._get_instance_name_from_tags(instance.get('tagSet', {}).get('items', []))
                                if instance_name:
                                    resource_info['instance_name'] = instance_name
                                
                                # Get IP addresses
                                resource_info['private_ip'] = instance.get('privateIpAddress', 'N/A')
                                resource_info['public_ip'] = instance.get('ipAddress', 'N/A')
                                resource_info['instance_type'] = instance.get('instanceType', 'Unknown')
                                break
                    
                    # If not found in CloudTrail, try to fetch from EC2 API
                    if 'instance_name' not in resource_info:
                        ec2_details = self._get_ec2_instance_details(instance_id, details['aws_region'], details.get('profile', 'default'))
                        if ec2_details:
                            resource_info.update(ec2_details)
                except:
                    pass
            
            details['resources'].append(resource_info)
        
        return details
    
    def _get_instance_name_from_tags(self, tags):
        """Extract instance name from tags"""
        for tag in tags:
            if tag.get('key') == 'Name':
                return tag.get('value', '')
        return None
    
    def _get_ec2_instance_details(self, instance_id: str, region: str, profile: str):
        """Fetch EC2 instance details from AWS API"""
        try:
            session = boto3.Session(profile_name=profile, region_name=region)
            ec2 = session.client('ec2')
            
            response = ec2.describe_instances(InstanceIds=[instance_id])
            
            if response['Reservations']:
                instance = response['Reservations'][0]['Instances'][0]
                
                # Get instance name from tags
                instance_name = None
                for tag in instance.get('Tags', []):
                    if tag['Key'] == 'Name':
                        instance_name = tag['Value']
                        break
                
                return {
                    'instance_name': instance_name or instance_id,
                    'instance_type': instance.get('InstanceType', 'Unknown'),
                    'private_ip': instance.get('PrivateIpAddress', 'N/A'),
                    'public_ip': instance.get('PublicIpAddress', 'N/A'),
                    'state': instance.get('State', {}).get('Name', 'Unknown')
                }
        except Exception as e:
            logger.debug(f"Could not fetch EC2 details for {instance_id}: {e}")
            return None
    
    def _get_event_category(self, event_name: str, event_source: str) -> str:
        """Categorize event for better organization"""
        categories = {
            'iam': ['User', 'Role', 'Policy', 'Group', 'AccessKey', 'MFA', 'Password', 'LoginProfile'],
            'ec2': ['Instance', 'SecurityGroup', 'Volume', 'Snapshot', 'Image', 'Address', 'KeyPair'],
            'network': ['Vpc', 'Subnet', 'Route', 'Gateway', 'Acl', 'Peering', 'Transit'],
            's3': ['Bucket', 'Object', 'Acl', 'Policy', 'Encryption', 'PublicAccess'],
            'rds': ['DBInstance', 'DBCluster', 'DBSnapshot', 'DBParameter', 'DBSubnet', 'DBSecurity', 'DBProxy'],
            'lambda': ['Function', 'Permission', 'EventSource', 'Alias', 'Concurrency'],
            'secrets': ['Secret', 'SecretValue', 'RotateSecret'],
            'ssm': ['Command', 'Document', 'Parameter', 'Session', 'Maintenance', 'Patch'],
            'cloudfront': ['Distribution', 'Origin', 'Invalidation', 'FieldLevel'],
            'acm': ['Certificate', 'Validation'],
            'security': ['Trail', 'Config', 'GuardDuty', 'SecurityHub', 'Detective'],
        }
        
        event_lower = event_name.lower()
        source_lower = event_source.lower()
        
        for category, keywords in categories.items():
            for keyword in keywords:
                if keyword.lower() in event_lower or keyword.lower() in source_lower:
                    return category
        
        return 'other'
    
    def _get_severity(self, event: Dict) -> str:
        """Determine event severity"""
        event_name = event.get('EventName', '')
        error_code = event.get('ErrorCode', '')
        
        # Critical severity events
        critical_patterns = [
            'Delete', 'Terminate', 'Disable', 'Stop', 'Revoke', 'Remove',
            'DeleteTrail', 'StopLogging', 'DisableKey', 'DeleteBucket',
            'DeleteDBInstance', 'DeleteFunction', 'DeleteSecret',
            'AuthorizeSecurityGroupIngress', 'PutBucketPolicy',
            'AssumeRole', 'CreateAccessKey', 'AttachUserPolicy', 'AttachRolePolicy'
        ]
        
        # High severity events
        high_patterns = [
            'Create', 'Update', 'Modify', 'Put', 'Add', 'Attach',
            'RunInstances', 'CreateUser', 'CreateRole', 'StartInstances'
        ]
        
        # Check for errors
        if error_code:
            if 'Unauthorized' in error_code or 'AccessDenied' in error_code:
                return 'WARNING'
        
        for pattern in critical_patterns:
            if pattern in event_name:
                return 'CRITICAL'
        
        for pattern in high_patterns:
            if pattern in event_name:
                return 'HIGH'
        
        return 'MEDIUM'
    
    def fetch_cloudtrail_events(self, profile: str, region: str) -> List[Dict]:
        """Fetch CloudTrail events for the last 10 minutes"""
        try:
            session = boto3.Session(profile_name=profile, region_name=region)
            cloudtrail = session.client('cloudtrail')
            
            # Get events from last 10 minutes (to catch delayed CloudTrail events)
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(minutes=10)
            
            events = []
            paginator = cloudtrail.get_paginator('lookup_events')
            
            for page in paginator.paginate(
                StartTime=start_time,
                EndTime=end_time,
                MaxResults=50
            ):
                for event in page.get('Events', []):
                    event_name = event.get('EventName', '')
                    
                    # Only process events we care about
                    if self._should_monitor_event(event_name):
                        # Create unique event ID
                        event_id = f"{profile}_{region}_{event.get('EventId', '')}"
                        
                        # Skip if already processed
                        if event_id not in self.processed_events:
                            # Get event details first to check if it's system-generated
                            event_details = self._get_event_details(event, profile)
                            
                            # Skip system-generated events (AWS service roles, automated backups, etc.)
                            if not self._is_system_generated_event(event_details):
                                events.append(event)
                                self.processed_events.add(event_id)
                            else:
                                # Still mark as processed to avoid checking again
                                self.processed_events.add(event_id)
                                logger.debug(f"Skipped system-generated event: {event_name} by {event_details.get('user_name', 'Unknown')}")
            
            return events
            
        except Exception as e:
            logger.error(f"Error fetching CloudTrail events for {profile} in {region}: {e}")
            return []
    
    def get_all_regions(self, profile: str) -> List[str]:
        """Get key AWS regions for faster processing"""
        # Use only major regions for faster processing during testing
        # In production, you can expand this list as needed
        return ['us-east-1', 'us-west-2', 'eu-west-1', 'eu-central-1', 
               'ap-south-1', 'ap-southeast-1']
    
    def monitor_all_accounts(self):
        """Monitor all AWS accounts and regions"""
        for profile in self.profiles:
            logger.info(f"Monitoring profile: {profile}")
            regions = self.get_all_regions(profile)
            
            for region in regions:
                events = self.fetch_cloudtrail_events(profile, region)
                
                for event in events:
                    details = self._get_event_details(event, profile)
                    details['severity'] = self._get_severity(event)
                    details['category'] = self._get_event_category(
                        event.get('EventName', ''),
                        event.get('EventSource', '')
                    )
                    
                    # Extract detailed change information
                    change_details = self._extract_change_details(details)
                    details['change_info'] = change_details
                    
                    # Group by profile and category
                    self.events_to_notify[profile][details['category']].append(details)
        
        # Save state after processing
        self._save_state()
    
    def generate_html_email(self) -> str:
        """Generate executive-friendly HTML email"""
        if not self.events_to_notify:
            logger.info("No events to generate email for")
            return None
        
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { 
                    font-family: 'Segoe UI', Arial, sans-serif; 
                    line-height: 1.6; 
                    color: #333;
                    background-color: #f4f4f4;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    background-color: white;
                    border-radius: 10px;
                    box-shadow: 0 0 20px rgba(0,0,0,0.1);
                    overflow: hidden;
                }
                .header {
                    background: #dc3545;
                    color: white;
                    padding: 30px;
                    text-align: center;
                    border-bottom: 4px solid #c82333;
                }
                .header h1 {
                    margin: 0;
                    font-size: 28px;
                    font-weight: 600;
                    color: white;
                    text-shadow: 1px 1px 2px rgba(0,0,0,0.3);
                }
                .header .subtitle {
                    margin-top: 10px;
                    font-size: 14px;
                    color: white;
                    font-weight: 500;
                }
                .summary {
                    background-color: #fff3cd;
                    border-left: 4px solid #ffc107;
                    padding: 20px;
                    margin: 20px;
                }
                .summary h2 {
                    color: #856404;
                    margin-top: 0;
                    font-size: 20px;
                }
                .stats {
                    display: flex;
                    justify-content: space-around;
                    padding: 20px;
                    background-color: #f8f9fa;
                }
                .stat-card {
                    text-align: center;
                    padding: 15px;
                    background: white;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    flex: 1;
                    margin: 0 10px;
                }
                .stat-card .number {
                    font-size: 32px;
                    font-weight: bold;
                    color: #667eea;
                }
                .stat-card .label {
                    color: #6c757d;
                    font-size: 14px;
                    margin-top: 5px;
                }
                .account-section {
                    margin: 20px;
                }
                .account-header {
                    background: #28a745;
                    color: white;
                    padding: 15px 20px;
                    border-radius: 8px 8px 0 0;
                    font-size: 18px;
                    font-weight: 600;
                    text-shadow: 1px 1px 2px rgba(0,0,0,0.2);
                }
                .category-section {
                    background: white;
                    border: 1px solid #dee2e6;
                    border-top: none;
                    margin-bottom: 20px;
                }
                .category-header {
                    background-color: #f8f9fa;
                    padding: 12px 20px;
                    border-bottom: 1px solid #dee2e6;
                    font-weight: 600;
                    color: #495057;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                .event-item {
                    padding: 15px 20px;
                    border-bottom: 1px solid #e9ecef;
                    transition: background-color 0.2s;
                }
                .event-item:hover {
                    background-color: #f8f9fa;
                }
                .event-item:last-child {
                    border-bottom: none;
                }
                .severity {
                    display: inline-block;
                    padding: 3px 8px;
                    border-radius: 4px;
                    font-size: 11px;
                    font-weight: 600;
                    text-transform: uppercase;
                }
                .severity-critical {
                    background-color: #dc3545;
                    color: white;
                }
                .severity-high {
                    background-color: #fd7e14;
                    color: white;
                }
                .severity-medium {
                    background-color: #ffc107;
                    color: #333;
                }
                .severity-warning {
                    background-color: #6c757d;
                    color: white;
                }
                .event-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 10px;
                }
                .event-name {
                    font-weight: 600;
                    color: #212529;
                    font-size: 15px;
                }
                .event-details {
                    color: #6c757d;
                    font-size: 13px;
                    line-height: 1.8;
                }
                .detail-row {
                    display: flex;
                    margin-bottom: 5px;
                }
                .detail-label {
                    font-weight: 600;
                    min-width: 120px;
                    color: #495057;
                }
                .detail-value {
                    color: #6c757d;
                }
                .resource-badge {
                    display: inline-block;
                    background-color: #e7f3ff;
                    color: #0066cc;
                    padding: 2px 8px;
                    border-radius: 12px;
                    font-size: 12px;
                    margin-right: 5px;
                }
                .ip-badge {
                    display: inline-block;
                    background-color: #fff0f0;
                    color: #cc0000;
                    padding: 2px 8px;
                    border-radius: 12px;
                    font-size: 12px;
                }
                .ip-info {
                    font-size: 12px;
                    color: #666;
                    background-color: #f8f9fa;
                    padding: 2px 6px;
                    border-radius: 4px;
                    margin-right: 5px;
                }
                .ec2-instance-info {
                    margin: 5px 0;
                    padding: 8px;
                    background-color: #f8f9fa;
                    border-radius: 4px;
                    border-left: 3px solid #667eea;
                }
                .footer {
                    background-color: #343a40;
                    color: white;
                    padding: 20px;
                    text-align: center;
                    font-size: 12px;
                }
                .footer a {
                    color: #667eea;
                    text-decoration: none;
                }
                .category-icon {
                    font-size: 16px;
                    margin-right: 8px;
                }
                .error-notice {
                    background-color: #f8d7da;
                    color: #721c24;
                    padding: 10px;
                    border-radius: 4px;
                    margin-top: 10px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>AWS Security Alert</h1>
                    <div class="subtitle">Critical Infrastructure Changes Detected</div>
                    <div class="subtitle">""" + datetime.now().strftime('%B %d, %Y at %I:%M %p') + """</div>
                </div>
        """
        
        # Calculate statistics
        total_events = sum(len(events) for profile_events in self.events_to_notify.values() 
                          for events in profile_events.values())
        critical_count = sum(1 for profile_events in self.events_to_notify.values() 
                           for events in profile_events.values() 
                           for event in events if event['severity'] == 'CRITICAL')
        affected_accounts = len(self.events_to_notify)
        
        # Add executive summary
        html += f"""
                <div class="summary">
                    <h2>📊 Executive Summary</h2>
                    <p><strong>{total_events}</strong> security-relevant changes detected across <strong>{affected_accounts}</strong> AWS account(s) in the last 5 minutes.</p>
                    <p>Immediate attention required for <strong>{critical_count}</strong> critical severity events.</p>
                </div>
                
                <div class="stats">
                    <div class="stat-card">
                        <div class="number">{total_events}</div>
                        <div class="label">Total Changes</div>
                    </div>
                    <div class="stat-card">
                        <div class="number">{critical_count}</div>
                        <div class="label">Critical Events</div>
                    </div>
                    <div class="stat-card">
                        <div class="number">{affected_accounts}</div>
                        <div class="label">Affected Accounts</div>
                    </div>
                    <div class="stat-card">
                        <div class="number">{len(set(r for p in self.events_to_notify.values() for c in p.values() for e in c for r in [e['aws_region']]))}</div>
                        <div class="label">Regions Affected</div>
                    </div>
                </div>
        """
        
        # Category icons
        category_icons = {
            'iam': '🔐',
            'ec2': '💻',
            'network': '🌐',
            's3': '🗄️',
            'rds': '🗃️',
            'lambda': '⚡',
            'kms': '🔑',
            'secrets': '🔒',
            'ssm': '⚙️',
            'cloudfront': '☁️',
            'acm': '📜',
            'security': '🛡️',
            'other': '📋'
        }
        
        # Add events by account and category
        for profile, categories in self.events_to_notify.items():
            html += f"""
                <div class="account-section">
                    <div class="account-header">
                        AWS Account: {profile.upper()}
                    </div>
            """
            
            # Check if there are any events to show
            if not categories:
                html += """
                    <div style="padding: 20px; text-align: center; color: #666;">
                        No events detected for this account.
                    </div>
                """
                continue
            
            for category, events in sorted(categories.items()):
                if not events:  # Skip empty categories
                    continue
                    
                icon = category_icons.get(category, '📋')
                html += f"""
                    <div class="category-section">
                        <div class="category-header">
                            <span><span class="category-icon">{icon}</span>{category.upper()} Changes</span>
                            <span>{len(events)} event(s)</span>
                        </div>
                """
                
                for event in sorted(events, key=lambda x: x['severity'] == 'CRITICAL', reverse=True):
                    severity_class = f"severity-{event['severity'].lower()}"
                    
                    # Format resource info with enhanced EC2 details
                    resource_html = ""
                    if event['resources']:
                        for resource in event['resources']:
                            if resource['type'] == 'AWS::EC2::Instance':
                                # Show EC2 instance with name and IPs
                                instance_display = resource.get('instance_name', resource['name'])
                                instance_type = resource.get('instance_type', 'Unknown')
                                private_ip = resource.get('private_ip', 'N/A')
                                public_ip = resource.get('public_ip', 'N/A')
                                state = resource.get('state', '')
                                
                                resource_html += f'<div class="ec2-instance-info">'
                                resource_html += f'<span class="resource-badge">Instance: <strong>{instance_display}</strong> ({instance_type})</span><br>'
                                resource_html += f'<span class="ip-info">Private IP: {private_ip}</span> | '
                                resource_html += f'<span class="ip-info">Public IP: {public_ip}</span>'
                                if state:
                                    resource_html += f' | <span class="ip-info">State: {state}</span>'
                                resource_html += f'</div>'
                            elif resource['type'] in ['AWS::EC2::SecurityGroup', 'AWS::EC2::KeyPair']:
                                # Show only security groups and key pairs for EC2 events
                                if resource['name']:
                                    resource_html += f'<span class="resource-badge">{resource["type"].split("::")[-1]}: {resource["name"]}</span>'
                    
                    # Special handling for SSM Sessions
                    ssm_session_info = ""
                    if event['event_name'] == 'StartSession' and event.get('ssm_target'):
                        ssm_session_info = f"""
                        <div class="detail-row">
                            <span class="detail-label">SSM Target:</span>
                            <span class="detail-value">{event.get('ssm_target')}</span>
                        </div>
                        """
                        if event.get('ssm_session_id'):
                            ssm_session_info += f"""
                            <div class="detail-row">
                                <span class="detail-label">Session ID:</span>
                                <span class="detail-value">{event.get('ssm_session_id')}</span>
                            </div>
                            """
                    
                    # Format error info if present
                    error_html = ""
                    if event.get('error_code'):
                        error_html = f"""
                        <div class="error-notice">
                            ⚠️ Error: {event['error_code']} - {event.get('error_message', '')}
                        </div>
                        """
                    
                    html += f"""
                        <div class="event-item">
                            <div class="event-header">
                                <span class="event-name">{event['event_name']}</span>
                                <span class="severity {severity_class}">{event['severity']}</span>
                            </div>
                            <div class="event-details">
                                <div class="detail-row">
                                    <span class="detail-label">Performed by:</span>
                                    <span class="detail-value">{event['user_name']} ({event['user_type']})</span>
                                </div>
                                <div class="detail-row">
                                    <span class="detail-label">Time:</span>
                                    <span class="detail-value">{event['event_time'].strftime('%Y-%m-%d %H:%M:%S UTC') if isinstance(event['event_time'], datetime) else event['event_time']}</span>
                                </div>
                                <div class="detail-row">
                                    <span class="detail-label">Region:</span>
                                    <span class="detail-value">{event['aws_region']}</span>
                                </div>
                                <div class="detail-row">
                                    <span class="detail-label">Source IP:</span>
                                    <span class="detail-value"><span class="ip-badge">{event['source_ip']}</span></span>
                                </div>
                    """
                    
                    if resource_html:
                        html += f"""
                                <div class="detail-row">
                                    <span class="detail-label">Resources:</span>
                                    <span class="detail-value">{resource_html}</span>
                                </div>
                        """
                    
                    # Add detailed change information
                    change_info = event.get('change_info', {})
                    if change_info and change_info.get('changes'):
                        change_summary = change_info.get('summary', '')
                        changes = change_info.get('changes', [])
                        
                        html += f"""
                                <div class="detail-row">
                                    <span class="detail-label">Changes Made:</span>
                                    <span class="detail-value"><strong>{change_summary}</strong></span>
                                </div>
                        """
                        
                        # Add detailed change list
                        for change in changes:
                            change_type = change.get('type', 'UNKNOWN')
                            change_desc = change.get('description', '')
                            
                            # Color code based on change type
                            change_badge_class = {
                                'ADDED': 'resource-badge',
                                'REMOVED': 'ip-badge', 
                                'MODIFIED': 'ip-info',
                                'CREATED': 'resource-badge',
                                'DELETED': 'ip-badge'
                            }.get(change_type, 'ip-info')
                            
                            html += f"""
                                <div class="detail-row" style="margin-left: 20px;">
                                    <span class="detail-label">• <span class="{change_badge_class}">{change_type}</span></span>
                                    <span class="detail-value">{change_desc}</span>
                                </div>
                            """
                    
                    if event['session_name']:
                        html += f"""
                                <div class="detail-row">
                                    <span class="detail-label">Session:</span>
                                    <span class="detail-value">{event['session_name']}</span>
                                </div>
                        """
                    
                    # Add SSM session info if available
                    html += ssm_session_info
                    
                    html += error_html
                    html += """
                            </div>
                        </div>
                    """
                
                html += """
                    </div>
                """
            
            html += """
                </div>
            """
        
        # Add footer
        html += """
                <div class="footer">
                    <p>This is an automated security alert from AWS Security Monitor</p>
                    <p>Generated at """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z') + """</p>
                    <p>For questions or to adjust monitoring settings, contact your Security Team</p>
                    <p><a href="#">View CloudTrail Logs</a> | <a href="#">Security Dashboard</a> | <a href="#">Incident Response Guide</a></p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def send_email_notification(self, html_content: str):
        """Send email using AWS SES"""
        if not html_content:
            logger.info("No events to notify")
            return
        
        try:
            # Use SES client with unified profile (where SES is configured)
            ses_profile = 'unified' if 'unified' in self.profiles else 'default'
            session = boto3.Session(profile_name=ses_profile)
            ses = session.client('ses', region_name='us-east-1')  # SES region
            logger.info(f"Using profile '{ses_profile}' for SES email")
            
            # Email configuration with friendly sender name
            from_email = 'Bamko Security Team <no-reply@bamko.net>'
            to_email = 'cmkhetwal@hotmail.com'
            subject = f"AWS Security Alert - {datetime.now().strftime('%Y-%m-%d %H:%M')} - {sum(len(e) for c in self.events_to_notify.values() for e in c.values())} Changes Detected"
            
            # Send email via SES
            response = ses.send_email(
                Source=from_email,
                Destination={'ToAddresses': [to_email]},
                Message={
                    'Subject': {
                        'Data': subject,
                        'Charset': 'UTF-8'
                    },
                    'Body': {
                        'Html': {
                            'Data': html_content,
                            'Charset': 'UTF-8'
                        }
                    }
                }
            )
            
            logger.info(f"Security alert email sent successfully via SES. MessageId: {response['MessageId']}")
            
        except Exception as e:
            logger.error(f"Failed to send email via SES: {e}")
    
    def run(self):
        """Main execution method"""
        logger.info("Starting AWS Security Monitor scan...")
        
        # Monitor all accounts
        self.monitor_all_accounts()
        
        # Generate and send email if there are events
        if self.events_to_notify:
            html_content = self.generate_html_email()
            self.send_email_notification(html_content)
            logger.info(f"Processed {sum(len(e) for c in self.events_to_notify.values() for e in c.values())} security events")
        else:
            logger.info("No security events detected in this scan")


def main():
    """Main entry point"""
    try:
        monitor = AWSSecurityMonitor()
        monitor.run()
    except Exception as e:
        logger.error(f"Fatal error in AWS Security Monitor: {e}")
        raise


if __name__ == "__main__":
    main()
