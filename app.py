#!/usr/bin/env python3

import aws_cdk as cdk

from gstn.gstn_stack import GstnStack


app = cdk.App()
GstnStack(app, "GstnStack")

app.synth()
