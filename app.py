import aws_cdk as cdk
import json
from constructs import Construct
from aws_cdk.aws_ec2 import IpAddresses
from aws_cdk import (
    Duration,
    Stack,
    aws_elasticloadbalancingv2 as elb,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_elasticloadbalancingv2 as elb,
    aws_autoscaling as autoscaling,
    aws_route53 as route53,
    aws_route53_targets as target,
    aws_s3 as s3,
    aws_ssm as ssm,
    aws_cloudwatch as cloudwatch,
    Fn,
    Tags
)

class ConnectedGstnInfra(Stack):
 
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        Tags.of(self).add("Project-Name", "CGSTN")

        with open('config.json', 'r') as config_file:
            config = json.load(config_file)

        EnvironmentName=config.get('EnvironmentName')
        VpcCIDR=config.get('VpcCIDR')
        cidr_mask = int(config.get('cidr_mask'))
        PrivateSubnet4CIDR=config.get('PrivateSubnet4CIDR')
        PrivateSubnet5CIDR=config.get('PrivateSubnet5CIDR')
        PrivateSubnet6CIDR=config.get('PrivateSubnet6CIDR')
        availability_zones=config.get('availability_zones')

        vpc = ec2.Vpc(
            self, EnvironmentName,
            ip_addresses=IpAddresses.cidr(VpcCIDR),
            availability_zones=availability_zones,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    subnet_type=ec2.SubnetType.PUBLIC,
                    name="Public",
                    cidr_mask=cidr_mask
                ),
                ec2.SubnetConfiguration(
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    name="Private",
                    cidr_mask=cidr_mask
                ),
            ],
            nat_gateways=0,
        )

        eip = ec2.CfnEIP(self, "EIP")
        nat_gateway = ec2.CfnNatGateway(self,"NAT",subnet_id=vpc.public_subnets[0].subnet_id,allocation_id=eip.attr_allocation_id)

        ssm.StringParameter(self, "VPCIDParameter",
            parameter_name="VPC_ID",
            string_value=vpc.vpc_id
        )


        private_subnet4 = ec2.PrivateSubnet(self, "MyPrivateSubnet4",
            availability_zone=availability_zones[0],
            cidr_block=PrivateSubnet4CIDR,
            vpc_id=vpc.vpc_id,
        )
        private_subnet4.add_default_nat_route(nat_gateway.attr_nat_gateway_id)
        ssm.StringParameter(self, "PrivateSubnet4ID",
            parameter_name="PrivateSubnet4ID",
            string_value=private_subnet4.subnet_id 
        )
        
        private_subnet5 = ec2.PrivateSubnet(self, "MyPrivateSubnet5",
            availability_zone=availability_zones[1],
            cidr_block=PrivateSubnet5CIDR,
            vpc_id=vpc.vpc_id,
        )
        private_subnet5.add_default_nat_route(nat_gateway.attr_nat_gateway_id)
        ssm.StringParameter(self, "PrivateSubnet5ID",
            parameter_name="PrivateSubnet5ID",
            string_value=private_subnet5.subnet_id 
        )

        private_subnet6 = ec2.PrivateSubnet(self, "MyPrivateSubnet6",
            availability_zone=availability_zones[2],
            cidr_block=PrivateSubnet6CIDR,
            vpc_id=vpc.vpc_id,
        )
        private_subnet6.add_default_nat_route(nat_gateway.attr_nat_gateway_id)
        ssm.StringParameter(self, "PrivateSubnet6ID",
            parameter_name="PrivateSubnet6ID",
            string_value=private_subnet6.subnet_id 
        )
        


        for subnet in vpc.private_subnets :
            subnet.add_default_nat_route(nat_gateway.attr_nat_gateway_id)

        i=1
        for subnet in vpc.private_subnets :
            ssm.StringParameter(self, "PrivateSubnet{}ID".format(i),
            parameter_name="PrivateSubnet{}ID".format(i),
            string_value=subnet.subnet_id 
            )
            i+=1

        i=1
        for subnet in vpc.public_subnets :
            ssm.StringParameter(self, "PublicSubnet{}ID".format(i),
            parameter_name="PublicSubnet{}ID".format(i),
            string_value=subnet.subnet_id 
            )
            i+=1

class Site1(Stack):
 
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        Tags.of(self).add("Project-Name", "CGSTN")

        with open('config.json', 'r') as config_file:
            config = json.load(config_file)

        cloudflare_ranges = [ "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17" ]

        ssl_certificate_arn=config.get('Certificatearn')
        public_ami_id = self.node.try_get_context('public_ami_id')
        internal_ami_id = self.node.try_get_context('internal_ami_id')
        region=config.get('region')
        VpcCIDR=config.get('VpcCIDR')
        availability_zones=config.get('availability_zones')
        role_arn = config.get('role_arn')
        InstanceType = config.get('instance_type')
        with open("tps_user_data.yaml", "r") as file:
            tps_user_data_yaml = file.read()
        with open("tgsp_user_data.yaml", "r") as file:
            tgsp_user_data_yaml = file.read()


        vpc_id=ssm.StringParameter.from_string_parameter_attributes(self, "vpc_id",parameter_name="VPC_ID").string_value
        PublicSubnet1ID=ssm.StringParameter.from_string_parameter_attributes(self, "PublicSubnet1ID",parameter_name="PublicSubnet1ID").string_value
        PublicSubnet2ID=ssm.StringParameter.from_string_parameter_attributes(self, "PublicSubnet2ID",parameter_name="PublicSubnet2ID").string_value
        PublicSubnet3ID=ssm.StringParameter.from_string_parameter_attributes(self, "PublicSubnet3ID",parameter_name="PublicSubnet3ID").string_value
        PrivateSubnet1ID=ssm.StringParameter.from_string_parameter_attributes(self, "PrivateSubnet1ID",parameter_name="PrivateSubnet1ID").string_value
        PrivateSubnet2ID=ssm.StringParameter.from_string_parameter_attributes(self, "PrivateSubnet2ID",parameter_name="PrivateSubnet2ID").string_value
        PrivateSubnet3ID=ssm.StringParameter.from_string_parameter_attributes(self, "PrivateSubnet3ID",parameter_name="PrivateSubnet3ID").string_value
        PrivateSubnet4ID=ssm.StringParameter.from_string_parameter_attributes(self, "PrivateSubnet4ID",parameter_name="PrivateSubnet4ID").string_value
        PrivateSubnet5ID=ssm.StringParameter.from_string_parameter_attributes(self, "PrivateSubnet5ID",parameter_name="PrivateSubnet5ID").string_value
        PrivateSubnet6ID=ssm.StringParameter.from_string_parameter_attributes(self, "PrivateSubnet6ID",parameter_name="PrivateSubnet6ID").string_value
        InternalALBLogsBucketName=config.get('InternalALBLogsBucketName')
        PublicALBLogsBucketName=config.get('PublicALBLogsBucketName')
        internal_alb_logs_bucket = s3.Bucket.from_bucket_name(self, "internal_alb_logs_bucket", InternalALBLogsBucketName)
        public_alb_logs_bucket = s3.Bucket.from_bucket_name(self, "public_alb_logs_bucket", PublicALBLogsBucketName)

        PublicSubnet1=ec2.Subnet.from_subnet_id(self, "PublicSubnet1", subnet_id=PublicSubnet1ID)
        PublicSubnet2=ec2.Subnet.from_subnet_id(self, "PublicSubnet2", subnet_id=PublicSubnet2ID)
        PublicSubnet3=ec2.Subnet.from_subnet_id(self, "PublicSubnet3", subnet_id=PublicSubnet3ID)
        max_capacity=config.get('max_capacity')
        min_capacity=config.get('min_capacity')
        desired_capacity=config.get('desired_capacity')
        NATIP=config.get('NATIP')


        PrivateSubnet1=ec2.Subnet.from_subnet_id(self, "PrivateSubnet1", subnet_id=PrivateSubnet3ID)
        PrivateSubnet2=ec2.Subnet.from_subnet_id(self, "PrivateSubnet2", subnet_id=PrivateSubnet2ID)
        PrivateSubnet3=ec2.Subnet.from_subnet_id(self, "PrivateSubnet3", subnet_id=PrivateSubnet1ID)
        PrivateSubnet4=ec2.Subnet.from_subnet_id(self, "PrivateSubnet4", subnet_id=PrivateSubnet4ID)
        PrivateSubnet5=ec2.Subnet.from_subnet_id(self, "PrivateSubnet5", subnet_id=PrivateSubnet5ID)
        PrivateSubnet6=ec2.Subnet.from_subnet_id(self, "PrivateSubnet6", subnet_id=PrivateSubnet6ID)


        role = iam.Role.from_role_arn(
            self, "ExistingRole", role_arn=role_arn
        )

        vpc = ec2.Vpc.from_vpc_attributes(self, "ImportedVpc", vpc_id=vpc_id, availability_zones=availability_zones,)


        internal_alb_security_group = ec2.SecurityGroup(self, "InternalALB",
            vpc=vpc,
            security_group_name="internal_alb_security_group1",
            description="Internal ALB Security group"
        )
        internal_alb_security_group.add_ingress_rule(
            ec2.Peer.ipv4(VpcCIDR),
            ec2.Port.tcp(443),
            description="Allow HTTPS Traffic"
        )

        public_alb_security_group = ec2.SecurityGroup(self, "PublicALB",
            vpc=vpc,
            security_group_name="public_alb_security_group1",
            description="Public ALB Security group1"
        )
        public_alb_security_group.add_ingress_rule(
            ec2.Peer.ipv4(NATIP),
            ec2.Port.tcp(443),
            description="Allow HTTPS Traffic"
        )
        for cidr in cloudflare_ranges:
            public_alb_security_group.add_ingress_rule(
                ec2.Peer.ipv4(cidr),
                ec2.Port.tcp(443),
                description=f"Allow HTTPS Traffic from {cidr}"
            )

        PublicALB = elb.ApplicationLoadBalancer(self, "public_alb",
            vpc=vpc,
            security_group=public_alb_security_group,
            vpc_subnets=ec2.SubnetSelection(subnets=[PublicSubnet1,PublicSubnet2,PublicSubnet3]),
            internet_facing=True  # Set to False if internal facing
        )
        PublicALB.log_access_logs(public_alb_logs_bucket, prefix=None)

        ssm.StringParameter(self, "ALB1URLParameter",
            parameter_name="Site1",
            string_value=PublicALB.load_balancer_dns_name
        )
       
       
        InternalALB = elb.ApplicationLoadBalancer(self, "internal_alb",
            vpc=vpc,
            security_group=internal_alb_security_group,
            vpc_subnets=ec2.SubnetSelection(subnets=[PrivateSubnet4,PrivateSubnet5,PrivateSubnet6]),
            internet_facing=False  # Set to False if internal facing
        )
        InternalALB.log_access_logs(internal_alb_logs_bucket, prefix=None)

        hosted_zone = route53.PrivateHostedZone(
            self,
            "PrivateHostedZone1",
            vpc=vpc,
            zone_name="site1.tallysolutions.com",
            comment="Private hosted zone"
        )
        route53.ARecord(
            self,
            "ALBRecord",
            zone=hosted_zone,
            target=route53.RecordTarget.from_alias(target.LoadBalancerTarget(InternalALB)),
        )

        asg_security_group=ec2.SecurityGroup(self, "ASG_SG",
            vpc=vpc,
            security_group_name="Autoscaling_security_group1",
            description="Autoscaling security group"
        )
        asg_security_group.add_ingress_rule(
            ec2.Peer.ipv4(VpcCIDR),
            ec2.Port.tcp(443),
            description="Allow HTTPS Traffic"
        )

        asg_security_group.add_ingress_rule(
            ec2.Peer.ipv4(VpcCIDR),
            ec2.Port.tcp(9999),
            description="Allow Custom Port Traffic"
        )

        public_asg = autoscaling.AutoScalingGroup(
            self,
            "TPS",
            vpc=vpc,
            instance_type=ec2.InstanceType(InstanceType),
            machine_image=ec2.MachineImage.generic_linux(ami_map={region: public_ami_id}),
            vpc_subnets=ec2.SubnetSelection(subnets=[PrivateSubnet1,PrivateSubnet2,PrivateSubnet3]),
            security_group=asg_security_group,
            role= role,
            user_data=ec2.UserData.custom(tps_user_data_yaml),
            min_capacity=min_capacity,
            desired_capacity=desired_capacity,
            max_capacity=max_capacity,
            health_check =autoscaling.HealthCheck.elb(grace=Duration.seconds(300))
        )

        autoscaling.LifecycleHook(
            self, "TerminationHook-Public",
            auto_scaling_group=public_asg,
            lifecycle_transition=autoscaling.LifecycleTransition.INSTANCE_TERMINATING,
            default_result=autoscaling.DefaultResult.CONTINUE,
            heartbeat_timeout=Duration.seconds(600)
        )


        Internal_asg = autoscaling.AutoScalingGroup(
            self,
            "TGSP",
            vpc=vpc,
            instance_type=ec2.InstanceType(InstanceType),
            machine_image=ec2.MachineImage.generic_linux(ami_map={region: internal_ami_id}),
            vpc_subnets=ec2.SubnetSelection(subnets=[PrivateSubnet4,PrivateSubnet5,PrivateSubnet6]),
            security_group=asg_security_group,
            min_capacity=min_capacity,
            desired_capacity=desired_capacity,
            max_capacity=max_capacity,
            role= role,
            user_data=ec2.UserData.custom(tgsp_user_data_yaml),
            health_check =autoscaling.HealthCheck.elb(grace=Duration.seconds(300))
        )
        autoscaling.LifecycleHook(
            self, "TerminationHook-Internal",
            auto_scaling_group=Internal_asg,
            lifecycle_transition=autoscaling.LifecycleTransition.INSTANCE_TERMINATING,
            default_result=autoscaling.DefaultResult.CONTINUE,
            heartbeat_timeout=Duration.seconds(600)
        )

        Internallistener = InternalALB.add_listener("InternalListener", port=443,certificates= [elb.ListenerCertificate.from_arn(ssl_certificate_arn)],open=False) 
        Internallistener.add_targets("InternalTarget", port=443, targets=[Internal_asg],health_check=elb.HealthCheck(path="/internalhealthcheck", port="443",healthy_http_codes="200"))

        Publiclistener = PublicALB.add_listener("PublicListener", port=443,certificates= [elb.ListenerCertificate.from_arn(ssl_certificate_arn)],open=False) 
        Publiclistener.add_targets("PublicTarget", port=443, targets=[public_asg],health_check=elb.HealthCheck(path="/internalhealthcheck", port="443",healthy_http_codes="200"))

        public_asg.scale_on_cpu_utilization("CpuScaling", target_utilization_percent = 70,estimated_instance_warmup=Duration.seconds(120), cooldown=Duration.seconds(120))
        public_asg.scale_on_request_count("RPSSCaling", target_requests_per_minute=2,estimated_instance_warmup=Duration.seconds(120), cooldown=Duration.seconds(120))
        public_asg.scale_on_metric(
            "MemoryScaling",
            metric=cloudwatch.Metric(
                metric_name="mem_used_percent",
                namespace="CWAgent",
                statistic="Average",
                dimensions_map={"AutoScalingGroupName": public_asg.auto_scaling_group_name},
            ),
            scaling_steps=[
                autoscaling.ScalingInterval(change=-1, lower=0, upper=30),
                autoscaling.ScalingInterval(change=1, lower=70),
            ],
            adjustment_type=autoscaling.AdjustmentType.CHANGE_IN_CAPACITY
        )

        Internal_asg.scale_on_cpu_utilization("CpuScaling",target_utilization_percent = 70,estimated_instance_warmup=Duration.seconds(120), cooldown=Duration.seconds(120))
        Internal_asg.scale_on_request_count("RPSSCaling", target_requests_per_minute=100,estimated_instance_warmup=Duration.seconds(120), cooldown=Duration.seconds(120))
        Internal_asg.scale_on_metric(
            "MemoryScaling",
            metric=cloudwatch.Metric(
                metric_name="mem_used_percent",
                namespace="CWAgent",
                statistic="Average",
                dimensions_map={"AutoScalingGroupName": Internal_asg.auto_scaling_group_name},
            ),
            scaling_steps=[
                autoscaling.ScalingInterval(change=-1, lower=0, upper=30),
                autoscaling.ScalingInterval(change=1, lower=70),
            ],
            adjustment_type=autoscaling.AdjustmentType.CHANGE_IN_CAPACITY
        )

class Site2(Stack):
 
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        Tags.of(self).add("Project-Name", "CGSTN")

        cloudflare_ranges = [ "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17" ]

        with open('config.json', 'r') as config_file:
            config = json.load(config_file)

        ssl_certificate_arn=config.get('Certificatearn')
        public_ami_id = self.node.try_get_context('public_ami_id')
        internal_ami_id = self.node.try_get_context('internal_ami_id')
        region=config.get('region')
        VpcCIDR=config.get('VpcCIDR')
        availability_zones=config.get('availability_zones')
        role_arn = config.get('role_arn')
        NATIP=config.get('NATIP')
        InstanceType = config.get('instance_type')
        with open("tps_user_data.yaml", "r") as file:
            tps_user_data_yaml = file.read()
        with open("tgsp_user_data.yaml", "r") as file:
            tgsp_user_data_yaml = file.read()

        vpc_id=ssm.StringParameter.from_string_parameter_attributes(self, "vpc_id",parameter_name="VPC_ID").string_value
        PublicSubnet1ID=ssm.StringParameter.from_string_parameter_attributes(self, "PublicSubnet1ID",parameter_name="PublicSubnet1ID").string_value
        PublicSubnet2ID=ssm.StringParameter.from_string_parameter_attributes(self, "PublicSubnet2ID",parameter_name="PublicSubnet2ID").string_value
        PublicSubnet3ID=ssm.StringParameter.from_string_parameter_attributes(self, "PublicSubnet3ID",parameter_name="PublicSubnet3ID").string_value
        PrivateSubnet1ID=ssm.StringParameter.from_string_parameter_attributes(self, "PrivateSubnet1ID",parameter_name="PrivateSubnet1ID").string_value
        PrivateSubnet2ID=ssm.StringParameter.from_string_parameter_attributes(self, "PrivateSubnet2ID",parameter_name="PrivateSubnet2ID").string_value
        PrivateSubnet3ID=ssm.StringParameter.from_string_parameter_attributes(self, "PrivateSubnet3ID",parameter_name="PrivateSubnet3ID").string_value
        PrivateSubnet4ID=ssm.StringParameter.from_string_parameter_attributes(self, "PrivateSubnet4ID",parameter_name="PrivateSubnet4ID").string_value
        PrivateSubnet5ID=ssm.StringParameter.from_string_parameter_attributes(self, "PrivateSubnet5ID",parameter_name="PrivateSubnet5ID").string_value
        PrivateSubnet6ID=ssm.StringParameter.from_string_parameter_attributes(self, "PrivateSubnet6ID",parameter_name="PrivateSubnet6ID").string_value
        InternalALBLogsBucketName=config.get('InternalALBLogsBucketName')
        PublicALBLogsBucketName=config.get('PublicALBLogsBucketName')
        internal_alb_logs_bucket = s3.Bucket.from_bucket_name(self, "internal_alb_logs_bucket", InternalALBLogsBucketName)
        public_alb_logs_bucket = s3.Bucket.from_bucket_name(self, "public_alb_logs_bucket", PublicALBLogsBucketName)

        PublicSubnet1=ec2.Subnet.from_subnet_id(self, "PublicSubnet1", subnet_id=PublicSubnet1ID)
        PublicSubnet2=ec2.Subnet.from_subnet_id(self, "PublicSubnet2", subnet_id=PublicSubnet2ID)
        PublicSubnet3=ec2.Subnet.from_subnet_id(self, "PublicSubnet3", subnet_id=PublicSubnet3ID)


        PrivateSubnet1=ec2.Subnet.from_subnet_id(self, "PrivateSubnet1", subnet_id=PrivateSubnet3ID)
        PrivateSubnet2=ec2.Subnet.from_subnet_id(self, "PrivateSubnet2", subnet_id=PrivateSubnet2ID)
        PrivateSubnet3=ec2.Subnet.from_subnet_id(self, "PrivateSubnet3", subnet_id=PrivateSubnet1ID)
        PrivateSubnet4=ec2.Subnet.from_subnet_id(self, "PrivateSubnet4", subnet_id=PrivateSubnet4ID)
        PrivateSubnet5=ec2.Subnet.from_subnet_id(self, "PrivateSubnet5", subnet_id=PrivateSubnet5ID)
        PrivateSubnet6=ec2.Subnet.from_subnet_id(self, "PrivateSubnet6", subnet_id=PrivateSubnet6ID)
        max_capacity=config.get('max_capacity')
        min_capacity=config.get('min_capacity')
        desired_capacity=config.get('desired_capacity')


        role = iam.Role.from_role_arn(
            self, "ExistingRole", role_arn=role_arn
        )

        vpc = ec2.Vpc.from_vpc_attributes(self, "ImportedVpc", vpc_id=vpc_id, availability_zones=availability_zones,)


        internal_alb_security_group = ec2.SecurityGroup(self, "InternalALB",
            vpc=vpc,
            security_group_name="internal_alb_security_group2",
            description="Internal ALB Security group"
        )
        internal_alb_security_group.add_ingress_rule(
            ec2.Peer.ipv4(VpcCIDR),
            ec2.Port.tcp(443),
            description="Allow HTTPS Traffic"
        )

        public_alb_security_group = ec2.SecurityGroup(self, "PublicALB",
            vpc=vpc,
            security_group_name="public_alb_security_group2",
            description="Public ALB Security group"
        )
        public_alb_security_group.add_ingress_rule(
            ec2.Peer.ipv4(NATIP),
            ec2.Port.tcp(443),
            description="Allow HTTPS Traffic"
        )
        for cidr in cloudflare_ranges:
            public_alb_security_group.add_ingress_rule(
                ec2.Peer.ipv4(cidr),
                ec2.Port.tcp(443),
                description=f"Allow HTTPS Traffic from {cidr}"
            )

        PublicALB = elb.ApplicationLoadBalancer(self, "public_alb",
            vpc=vpc,
            security_group=public_alb_security_group,
            vpc_subnets=ec2.SubnetSelection(subnets=[PublicSubnet1,PublicSubnet2,PublicSubnet3]),
            internet_facing=True 
        )
        PublicALB.log_access_logs(public_alb_logs_bucket, prefix=None)

        ssm.StringParameter(self, "ALB2URLParameter",
            parameter_name="Site2",
            string_value=PublicALB.load_balancer_dns_name
        )
       
       
        InternalALB = elb.ApplicationLoadBalancer(self, "internal_alb",
            vpc=vpc,
            security_group=internal_alb_security_group,
            vpc_subnets=ec2.SubnetSelection(subnets=[PrivateSubnet4,PrivateSubnet5,PrivateSubnet6]),
            internet_facing=False  # Set to False if internal facing
        )
        InternalALB.log_access_logs(internal_alb_logs_bucket, prefix=None)

        hosted_zone = route53.PrivateHostedZone(
            self,
            "PrivateHostedZone2",
            vpc=vpc,
            zone_name="site2.tallysolutions.com",
            comment="Private hosted zone"
        )
        route53.ARecord(
            self,
            "ALBRecord2",
            zone=hosted_zone,
            target=route53.RecordTarget.from_alias(target.LoadBalancerTarget(InternalALB)),
        )

        asg_security_group=ec2.SecurityGroup(self, "ASG_SG",
            vpc=vpc,
            security_group_name="Autoscaling_security_group2",
            description="Autoscaling security group"
        )
        asg_security_group.add_ingress_rule(
            ec2.Peer.ipv4(VpcCIDR),
            ec2.Port.tcp(443),
            description="Allow HTTPS Traffic"
        )

        asg_security_group.add_ingress_rule(
            ec2.Peer.ipv4(VpcCIDR),
            ec2.Port.tcp(9999),
            description="Allow Custom Port Traffic"
        )

        public_asg = autoscaling.AutoScalingGroup(
            self,
            "TPS",
            vpc=vpc,
            instance_type=ec2.InstanceType(InstanceType),
            machine_image=ec2.MachineImage.generic_linux(ami_map={region: public_ami_id}),
            vpc_subnets=ec2.SubnetSelection(subnets=[PrivateSubnet1,PrivateSubnet2,PrivateSubnet3]),
            security_group=asg_security_group,
            role= role,
            user_data=ec2.UserData.custom(tps_user_data_yaml),
            min_capacity=min_capacity,
            desired_capacity=desired_capacity,
            max_capacity=max_capacity,
            health_check =autoscaling.HealthCheck.elb(grace=Duration.seconds(300))
        )

        autoscaling.LifecycleHook(
            self, "TerminationHook-Public",
            auto_scaling_group=public_asg,
            lifecycle_transition=autoscaling.LifecycleTransition.INSTANCE_TERMINATING,
            default_result=autoscaling.DefaultResult.CONTINUE,
            heartbeat_timeout=Duration.seconds(600)
        )


        Internal_asg = autoscaling.AutoScalingGroup(
            self,
            "TGSP",
            vpc=vpc,
            instance_type=ec2.InstanceType(InstanceType),
            machine_image=ec2.MachineImage.generic_linux(ami_map={region: internal_ami_id}),
            vpc_subnets=ec2.SubnetSelection(subnets=[PrivateSubnet4,PrivateSubnet5,PrivateSubnet6]),
            security_group=asg_security_group,
            min_capacity=min_capacity,
            desired_capacity=desired_capacity,
            max_capacity=max_capacity,
            role= role,
            user_data=ec2.UserData.custom(tgsp_user_data_yaml),
            health_check =autoscaling.HealthCheck.elb(grace=Duration.seconds(300))
        )
        autoscaling.LifecycleHook(
            self, "TerminationHook-Internal",
            auto_scaling_group=Internal_asg,
            lifecycle_transition=autoscaling.LifecycleTransition.INSTANCE_TERMINATING,
            default_result=autoscaling.DefaultResult.CONTINUE,
            heartbeat_timeout=Duration.seconds(600)
        )
        Internallistener = InternalALB.add_listener("InternalListener", port=443,certificates= [elb.ListenerCertificate.from_arn(ssl_certificate_arn)],open=False) 
        Internallistener.add_targets("InternalTarget", port=443, targets=[Internal_asg],health_check=elb.HealthCheck(path="/internalhealthcheck", port="443",healthy_http_codes="200"))

        Publiclistener = PublicALB.add_listener("PublicListener", port=443,certificates= [elb.ListenerCertificate.from_arn(ssl_certificate_arn)],open=False) 
        Publiclistener.add_targets("PublicTarget", port=443, targets=[public_asg],health_check=elb.HealthCheck(path="/internalhealthcheck", port="443",healthy_http_codes="200"))

        public_asg.scale_on_cpu_utilization("CpuScaling", target_utilization_percent = 70,estimated_instance_warmup=Duration.seconds(120), cooldown=Duration.seconds(120))
        public_asg.scale_on_request_count("RPSSCaling", target_requests_per_minute=2,estimated_instance_warmup=Duration.seconds(120), cooldown=Duration.seconds(120))
        public_asg.scale_on_metric(
            "MemoryScaling",
            metric=cloudwatch.Metric(
                metric_name="mem_used_percent",
                namespace="CWAgent",
                statistic="Average",
                dimensions_map={"AutoScalingGroupName": public_asg.auto_scaling_group_name},
            ),
            scaling_steps=[
                autoscaling.ScalingInterval(change=-1, lower=0, upper=30),
                autoscaling.ScalingInterval(change=1, lower=70),
            ],
            adjustment_type=autoscaling.AdjustmentType.CHANGE_IN_CAPACITY
        )

        Internal_asg.scale_on_cpu_utilization("CpuScaling",target_utilization_percent = 70,estimated_instance_warmup=Duration.seconds(120), cooldown=Duration.seconds(120))
        Internal_asg.scale_on_request_count("RPSSCaling", target_requests_per_minute=100,estimated_instance_warmup=Duration.seconds(120), cooldown=Duration.seconds(120))
        Internal_asg.scale_on_metric(
            "MemoryScaling",
            metric=cloudwatch.Metric(
                metric_name="mem_used_percent",
                namespace="CWAgent",
                statistic="Average",
                dimensions_map={"AutoScalingGroupName": Internal_asg.auto_scaling_group_name},
            ),
            scaling_steps=[
                autoscaling.ScalingInterval(change=-1, lower=0, upper=30),
                autoscaling.ScalingInterval(change=1, lower=70),
            ],
            adjustment_type=autoscaling.AdjustmentType.CHANGE_IN_CAPACITY
        )


  

with open('config.json', 'r') as config_file:
    config = json.load(config_file)
region=config.get('region')
# region = "ap-south-1"
app = cdk.App()
ConnectedGstnInfra(app, "ConnectedGstnInfra", env={'region': region})
Site1(app, "Site1", env={'region': region})
Site2(app, "Site2", env={'region': region})

app.synth()
